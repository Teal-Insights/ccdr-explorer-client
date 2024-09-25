import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


if __name__ == "__main__":
    import argparse
    import os
    from dotenv import load_dotenv
    from utils.db import set_up_db

    load_dotenv()

    parser = argparse.ArgumentParser(
        description="Optionally drop and recreate all tables in the database and set up default roles and permissions"
    )
    parser.add_argument(
        "--drop",
        action="store_true",
        help="Drop all tables first"
    )

    args = parser.parse_args()

    set_up_db(args.drop)

    print(
        f"Set up database {os.getenv('DB_NAME')}"
    )
