To create the index with some dynamic templates :

curl -XPUT -d @index_settings.json localhost:9200/zentral-events

To delete the index :

curl -XDELETE localhost:9200/zentral-events
