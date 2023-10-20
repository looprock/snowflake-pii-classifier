#!/usr/bin/env python
import snowflake.connector
import os
import sys
import argparse
import logging
import json

# TODO: 
# scope down / replace requirement for accountadmin role
# find tables with existing tags and remove them from list of, or maybe use a cache?

if not os.getenv('SNOWSQL_USER'):
    sys.exit("ERROR: you must provide the environment variable 'SNOWSQL_USER' with a valid snowflake username!")
snow_user = os.getenv('SNOWSQL_USER')

if not os.getenv('SNOWSQL_PASS'):
    sys.exit("ERROR: you must provide the environment variable 'SNOWSQL_PASS' with a valid snowflake password!")
snow_pass = os.getenv('SNOWSQL_PASS')

account = os.getenv('SNOWSQL_ACCOUNT', '[id].[region]')
warehouse=os.getenv('SNOWSQL_WH', 'TESTWH')
database=os.getenv('SNOWSQL_DB', 'TESTDB')
schema=os.getenv('SNOWSQL_SCHEMA','PUBLIC')

parser = argparse.ArgumentParser()
parser.add_argument("--tables", help="Override: comma separated list of tables to tag.", type=str, required=False)
parser.add_argument("--excludes", help="Override: comma separated list of tables to exclude.", type=str, required=False)
parser.add_argument("--noclassify", help="Disable the classifier portion of the script", action="store_true")
parser.add_argument("--debug", help="Enable debug mode", action="store_true")
args = parser.parse_args()

# snowflake.connector is very chatty
logging.getLogger('snowflake.connector').setLevel(logging.WARNING)
if args.debug:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
else:
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
logger = logging.getLogger()

if args.excludes:
    excludes = args.excludes.split(",")
else:
    excludes = []

if excludes:
    logger.info(f"Excluding: {excludes}")

ctx = snowflake.connector.connect(
    user=snow_user,
    password=snow_pass,
    account=account,
    database=database,
    warehouse=warehouse,
    schema=schema,
    )
cs = ctx.cursor()

def get_columns(table_name):
    result = cs.execute(f"SELECT EXTRACT_SEMANTIC_CATEGORIES('{database}.{schema}.{table_name}')").fetchall()
    rjson = json.loads(result[0][0])
    tmp_list = []
    for i in rjson.keys():
        if 'recommendation' in rjson[i].keys():
            tmp_list.append(i)
    return tmp_list

def main():
    try:
        logger.info(f"Operating on: {warehouse}.{database}.{schema}...")
        cs.execute("USE ROLE accountadmin")
        # create roles
        logger.info("Creating roles SANDBOX_UNMASKED_READ_ROLE (if not exist)...")
        cs.execute("CREATE ROLE IF NOT EXISTS SANDBOX_SANDBOX_UNMASKED_READ_ROLE COMMENT = 'Read only unmasked view of data in SANDBOX'")
        cs.execute(f"GRANT USAGE ON DATABASE {database} TO ROLE SANDBOX_UNMASKED_READ_ROLE")
        cs.execute(f"GRANT USAGE ON SCHEMA {database}.{schema} TO ROLE SANDBOX_UNMASKED_READ_ROLE")
        cs.execute(f"GRANT USAGE ON WAREHOUSE {warehouse} TO ROLE SANDBOX_UNMASKED_READ_ROLE")
        cs.execute(f"GRANT CREATE SCHEMA on DATABASE {database} TO ROLE SANDBOX_UNMASKED_READ_ROLE")
        logger.info("Create tag IF NOT EXISTS...")
        cs.execute(f"create tag IF NOT EXISTS {database}.{schema}.PII_DETECTED")
        # get a list of all tables
        logger.info("Getting a list of all tables...")
        # accept a comma separated list of tables as first argument
        if args.tables:
            all_tables = args.tables.split(",")
        else:
            # otherwise, for no argument, get a list of all existing tables
            all_tables = []
            table_names = cs.execute(f"SHOW TABLES IN {database}.{schema}").fetchall()
            for table_name in table_names:
                logger.debug(f"Adding table: {table_name[1]}")
                all_tables.append(table_name[1])
        # tag all PRIVACY_CATEGORY items with a new non-system tag PII_DETECTED
        logger.info("Classifying all table data...")
        # classify all tables
        if args.noclassify:
            logger.info("Skipping classification process")
        else:
            logger.info("Tagging all PRIVACY_CATEGORY data with PII_DETECTED...")
            logging.debug(all_tables)
            for table in all_tables:
                if table not in excludes:
                    logger.info(f"Processing {table}")
                    columns = get_columns(table)
                    for column in columns:
                        tag_sql = f"alter table {database}.{schema}.{table} modify column \"{column}\" set tag PII_DETECTED = 'true'"
                        logger.debug(tag_sql)
                        cs.execute(tag_sql)
        logger.info("Creating masking policy...")
        cs.execute("""create masking policy if not exists mask_pii as
     (val string) returns string ->
    case
     when current_role() in ('SANDBOX_UNMASKED_READ_ROLE') then val
     else '**masked**'
    end""")
        # apply making policy
        logger.info("Setting masking policy...")
        cs.execute(f"alter tag {database}.{schema}.PII_DETECTED set masking policy mask_pii")
        # grant access to the masked and unmasked roles (only after everything else is done):
        logger.info("Granting access to both SANDBOX_UNMASKED_READ_ROLE and SANDBOX_MASKED_READ_ROLE roles...")
        for table_name in all_tables:
            grant1_sql = f"GRANT SELECT ON {database}.{schema}.{table_name} TO ROLE SANDBOX_UNMASKED_READ_ROLE"
            logger.debug(grant1_sql)
            cs.execute(grant1_sql)
    finally:
        cs.close()
    ctx.close()

if __name__ == '__main__':
    main()
