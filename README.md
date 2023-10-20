# snowflake-pii-classifier
Use snowflake's EXTRACT_DEMANTIC_CATEGORIES to automatically tag PII and mask from everything but one role.

# Usage
pii_tagger iterate through all tables in a schema and tags columns identified as PRIVACY_CATEGORY by snowflake classifiers with a secondary tag which can be used by a tag-based masking policy. There is a restriction where system tags (such as PRIVACY_CATEGORY) cannot be used with tag-based masking policies making this necessary. This script will also grant select to the two pre-defined roles we will use for access to the data:

- SANDBOX_UNMASKED_READ_ROLE

# before you begin
* export the following environment variables: SNOWSQL_USER, SNOWSQL_PASS OPTIONAL: SNOWSQL_ACCOUNT, SNOWSQL_DB, SNOWSQL_WH, SNOWSQL_SCHEMA
* *definitely needs to be turned into comprehensive script/bot ideally ran from a workflow*


# run classify.py

this will populate the custom tag 'PII_DETECTED' to everything classified as PRIVACY_CATEGORY by classifiers
```
poetry install
poetry shell
./classify.py
```

# Options
```
--tables - Override: comma separated list of tables to tag
--excludes - Override: comma separated list of tables to exclude
--noclassify - Disable the classifier portion of the script
--debug - Enable debug mode
```


## To disable the policy
- alter tag PII_DETECTED unset masking policy mask_pii;
