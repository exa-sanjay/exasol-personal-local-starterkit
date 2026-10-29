"""Seed the spike's Iceberg catalog: namespace `shop`, table `orders` (3 rows)."""
import datetime as dt

import pyarrow as pa
from pyiceberg.catalog import load_catalog

cat = load_catalog("spike", **{
    "type": "rest",
    "uri": "http://localhost:18181",
    "s3.endpoint": "http://localhost:19000",
    "s3.access-key-id": "lhadmin",
    "s3.secret-access-key": "lhadminsecret123",
    "s3.region": "us-east-1",
    "s3.path-style-access": "true",
})
if ("shop",) not in cat.list_namespaces():
    cat.create_namespace("shop")
data = pa.table({
    "order_id": pa.array([1, 2, 3], pa.int64()),
    "customer": pa.array(["Acme", "Globex", "Initech"]),
    "amount": pa.array([19.99, 250.0, 7.5], pa.float64()),
    "ordered_at": pa.array([dt.date(2026, 10, 1), dt.date(2026, 10, 2), dt.date(2026, 10, 3)], pa.date32()),
})
if cat.table_exists("shop.orders"):
    cat.drop_table("shop.orders")
t = cat.create_table("shop.orders", schema=data.schema)
t.append(data)
print("rows:", len(t.scan().to_arrow()), "location:", t.location())
