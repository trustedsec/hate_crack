"""Seed a local Hashview docker stack to the state hate_crack's live tests need.

Runs INSIDE the Hashview ``app`` container (``PYTHONPATH=/``), where the
``hashview`` package is importable. Idempotent.

Brings the database to:
- admin user (id=1) with a known ``api_key`` (so hate_crack can authenticate)
- a Settings row (so the /setup wizard does not intercept requests)
- a Customer at ``HASHVIEW_CUSTOMER_ID``
- a Hashfile at ``HASHVIEW_HASHFILE_ID`` holding one (uncracked) hash, so the
  ``download-hashes`` / left-list endpoints return data
- at least one *cracked* Hashes row per hash type in
  ``HASHVIEW_SEED_HASH_TYPES`` (comma separated, default ``0,1000``) attached to
  a real Task. ``/v1/jobs/add`` derives its "top 10 effective tasks" from
  cracked hashes of the uploaded file's hash type; without this it answers
  "Not enough data to determine effective tasks" and job creation fails.

Required env: HASHVIEW_API_KEY, HASHVIEW_CUSTOMER_ID, HASHVIEW_HASHFILE_ID.
Optional env: HASHVIEW_SEED_HASH_TYPES, HASHVIEW_SEED_TASK_ID (default 1).
"""
import os
import sys

from flask import Flask
from flask_bcrypt import Bcrypt

from hashview.config import Config
from hashview.models import (
    Customers,
    Hashes,
    HashfileHashes,
    Hashfiles,
    Settings,
    Tasks,
    Users,
    db,
)

REQUIRED_ENV = (
    "HASHVIEW_API_KEY",
    "HASHVIEW_CUSTOMER_ID",
    "HASHVIEW_HASHFILE_ID",
)


def build_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    Bcrypt(app)
    return app


def seed(app: Flask) -> None:
    api_key = os.environ["HASHVIEW_API_KEY"]
    customer_id = int(os.environ["HASHVIEW_CUSTOMER_ID"])
    hashfile_id = int(os.environ["HASHVIEW_HASHFILE_ID"])
    task_id = int(os.environ.get("HASHVIEW_SEED_TASK_ID", "1"))
    hash_types = [
        int(x) for x in os.environ.get("HASHVIEW_SEED_HASH_TYPES", "0,1000").split(",") if x.strip()
    ]

    bcrypt = Bcrypt(app)

    with app.app_context():
        admin = db.session.get(Users, 1)
        if admin is None:
            raise RuntimeError(
                "Admin user (id=1) not found. App must finish booting before seeding."
            )
        admin.api_key = api_key
        admin.admin = True
        # Hashview's setup guard (do_gui_setup_if_needed) redirects every request
        # to /setup/admin-pass while the admin password is still the default.
        # Set a non-default password so the API is reachable without the wizard.
        admin.password = bcrypt.generate_password_hash(
            os.environ.get("HASHVIEW_ADMIN_PASSWORD", "hate-crack-local-pass")
        ).decode("utf-8")
        admin.email_address = admin.email_address or "admin@hate-crack.local"

        if db.session.query(Settings).first() is None:
            db.session.add(
                Settings(retention_period=30, max_runtime_jobs=0, max_runtime_tasks=0)
            )

        if db.session.get(Customers, customer_id) is None:
            db.session.add(Customers(id=customer_id, name="hate_crack Local Customer"))

        if db.session.get(Tasks, task_id) is None:
            raise RuntimeError(
                f"Task id={task_id} not found. Default tasks should exist after app boot."
            )

        if db.session.get(Hashfiles, hashfile_id) is None:
            db.session.add(
                Hashfiles(
                    id=hashfile_id,
                    name="hate-crack-local-hashfile",
                    customer_id=customer_id,
                    owner_id=admin.id,
                )
            )
            db.session.flush()
            hash_row = Hashes(
                sub_ciphertext="d41d8cd98f00b204e9800998ecf8427e",
                ciphertext="d41d8cd98f00b204e9800998ecf8427e",
                hash_type=0,
                cracked=False,
            )
            db.session.add(hash_row)
            db.session.flush()
            db.session.add(
                HashfileHashes(
                    hash_id=hash_row.id, username="local-user", hashfile_id=hashfile_id
                )
            )

        # Cracked "effective task" data, one row per hash type the tests upload.
        for ht in hash_types:
            sub = f"seed-cracked-{ht}"
            exists = (
                db.session.query(Hashes)
                .filter_by(sub_ciphertext=sub, hash_type=ht, cracked=True)
                .first()
            )
            if exists is None:
                db.session.add(
                    Hashes(
                        sub_ciphertext=sub,
                        ciphertext=sub,
                        hash_type=ht,
                        cracked=True,
                        task_id=task_id,
                        plaintext="password",
                    )
                )

        db.session.commit()


def main() -> int:
    missing = [k for k in REQUIRED_ENV if not os.getenv(k)]
    if missing:
        print(f"hashview_local_seed: missing env vars: {missing}", file=sys.stderr)
        return 2
    seed(build_app())
    print("hashview_local_seed: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
