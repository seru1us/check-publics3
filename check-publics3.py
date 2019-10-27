
import boto3
import json
import sys
import time
import sqlite3
from sqlite3 import Error
from logging.handlers import SysLogHandler
import logging

######################################## Hard Coded Variables ########################################
# Ideally this would go in a different file, but since this is so short putting them here will suffice.

# define where we are keeping the db... in this case its in the same dir
sqlite_file = 's3_bucket_state.db'

# Set up the logging handler. In a production environment, SysLogHandler would be configured to export
# events to an external log aggregator or SIEM.
# TODO: As it stands, this is hardly rfc5424. Getting the output into a standard format will be a first
# priority for putting this into a production environment.
logger = logging.getLogger()
logger.addHandler(SysLogHandler('/dev/log'))
logger.addHandler(logging.FileHandler("check-publics3.log"))

##################################### End Hard Coded Variables ########################################

s3 = boto3.client('s3')

# Create a simple sqlite db if it doesn't exist. This is pretty basic, and doesn't really check the to see if the current
# db is valid. Realistically I would add some sanity checks to make sure the data in it is healthy. Anyways it just creates
# one if it can't connect
def initialize_sqlite_db(sqlite_file):
    sqlconn = None
    try: 
        # This should just make a db file if it doesn't exist.
        sqlconn = sqlite3.connect(sqlite_file)
    except Error as sqlite_error:
        # This honestly shouldn't ever happen, but assuming something won't fail is always a bad idea.
        print(sqlite_error)
        sys.exit()
    finally:
        if sqlconn:
            # Make sure our table exists, and if it doesn't create it.
            curse = sqlconn.cursor()
            curse.execute(''' SELECT count(name) FROM sqlite_master WHERE type='buckets' ''')
            if curse.fetchone()[0]!=1 : {
                # NOTE: We are going to use UNIX time format just for simplicity's sake. 
            	curse.execute(""" CREATE TABLE IF NOT EXISTS buckets (
                                        id integer PRIMARY KEY,
                                        name text NOT NULL UNIQUE,
                                        last_seen_permission text,
                                        last_seen_date text
                                    ); """)
            }
            return sqlconn

# Simple function which returns all the buckets our account has access to
def get_s3_buckets():
    # Call S3 to list current buckets
    response = s3.list_buckets()

    # Get a list of all bucket names from the response
    buckets = [bucket['Name'] for bucket in response['Buckets']]

    return buckets

# This cycles through all of the buckets returned from "get_s3_buckets" and determines what to do with the returned info. 
def evaluate_s3_buckets(buckets):
    for bucket in buckets:
        # All the relevant info for if a bucket is publicly accessible should be in the ACL endpoint.
        result = s3.get_bucket_acl(Bucket=bucket)
        # Most everything below is just filtering through the json/dicts that are returned from boto3 to find the 
        # appropriate value (URI). If it finds that there is public access, it will record the specific permission
        # given to public requests. Otherwise, it doesn't. 
        # print(bucket)
        # The below check to see if there is only a single grant tells us that this bucket only has the default permissions
        # for the owner of the bucket, and can't be public (would require an additional grant).
        #  We'll skip it but record its presence nonetheless.
        if len(result['Grants']) == 1:
            write_s3_state(bucket, 'notpublic')
        # Now for the fun part. Checking for keys that may or not exist in python is always a blast /s
        # Here I'm going to create a new array of all the URIs that exist in all the grants, and check for public access
        # attributes from there. There is probably a better way to do this (most definitely) and I'll figure it out given more time.
        else:
            public_result = []
            for grant in result['Grants']:
                try:
                    if grant['Grantee']['URI'] == 'http://acs.amazonaws.com/groups/global/AllUsers':
                        public_result.append(grant['Permission'])
                except KeyError:
                    pass
            # If there are no results for the public_resutls array, then we didn't find any matches.
            if len(public_result) == 0:
                write_s3_state(bucket, 'notpublic')
            else: 
            # If we did find matches, record which permissions were given and save state.
                write_s3_state(bucket, " ".join(str(x) for x in public_result))

# This gets called once an s3 bucket has been scanned and updates the DB accordingly, as well as any
# additional notifications that are required.
def write_s3_state(bucket, pubperm):
    # First things first warm up the db
    sqlconn = initialize_sqlite_db(sqlite_file)
    curse = sqlconn.cursor()
    # And then see if we know whether this bucket exists already or not.
    curse.execute("SELECT rowid FROM buckets WHERE name=?", (bucket,))
    current_db_row = curse.fetchall()
    # If the following is TRUE, then this is the first time we've seen this. Write our DB entry and 
    # create a notification.
    if len(current_db_row) == 0:
        curse.execute("INSERT INTO buckets ('name', 'last_seen_permission', 'last_seen_date') VALUES (?, ?, ?);", (bucket, pubperm, time.time(),))
        sqlconn.commit()
        notify_on_event(bucket, pubperm, 'New Public ACL')
    # If we DO NOT find 0 results from our query, then we have seen this bucket before. Time to check if
    # anything has changed since then. If it hasn't, just update the last seen column. Otherwise, update
    # and notify.
    elif len(current_db_row) == 1:
        rowid = current_db_row[0]
        curse.execute("SELECT * FROM buckets WHERE rowid=?", (rowid))
        current_db_row = curse.fetchall()
        # Now that we have both the prior and current state of our target s3 bucket "bucket", we can compare the two
        # and notify accordingly. We'll start with whether our current query returned public or not, and then compare it
        # against our historical data.
        if pubperm != 'notpublic':
            # The below uses hard-coded array references which I don't like, and given more time I would change this to 
            # something more scalable and presentable. But for now it works and I can control the data structure.
            if current_db_row[0][2] == 'notpublic':
                # If we have come this far, that means our target bucket's state has changed from private to public, and
                # we need to notify accordingly.
                notify_on_event(bucket, pubperm, 'Changed to Public from Private')
            else:
                # This will notify that the bucket is public, and was public last time we scanned it.
                # NOTE: If I was maintaining this I would implement a whitelist for any buckets that do, in fact, need to be
                # public. That wasn't an explicit requirement here but I can see the benefit of it in some cases.
                notify_on_event(bucket, pubperm, 'Is Public now, and was public previously')
        # Regardless of the prior state, we'll update the row with what we just discovered.
        curse.execute("UPDATE buckets SET last_seen_permission=?, last_seen_date=? WHERE rowid=?", (pubperm, time.time(), rowid[0],))
        sqlconn.commit()
        sqlconn.close()


def notify_on_event(bucket, pubperm, message):
    message = "s3 bucket " + bucket + " has been detected as public with the permissions " + pubperm + " and the status message: " + message
    logging.warning(message)

def main():
    # Create an S3 client
    evaluate_s3_buckets(get_s3_buckets())

if __name__== "__main__":
  main()
