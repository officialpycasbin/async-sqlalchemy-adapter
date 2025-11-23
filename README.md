async-sqlalchemy-adapter
====

[![build](https://github.com/officialpycasbin/async-sqlalchemy-adapter/actions/workflows/build.yml/badge.svg)](https://github.com/officialpycasbin/async-sqlalchemy-adapter/actions/workflows/build.yml)
[![Coverage Status](https://coveralls.io/repos/github/officialpycasbin/async-sqlalchemy-adapter/badge.svg)](https://coveralls.io/github/officialpycasbin/async-sqlalchemy-adapter)
[![Version](https://img.shields.io/pypi/v/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![PyPI - Wheel](https://img.shields.io/pypi/wheel/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![Pyversions](https://img.shields.io/pypi/pyversions/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![Download](https://static.pepy.tech/badge/casbin-async-sqlalchemy-adapter)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)
[![License](https://img.shields.io/pypi/l/casbin_async_sqlalchemy_adapter.svg)](https://pypi.org/project/casbin_async_sqlalchemy_adapter/)

Asynchronous SQLAlchemy Adapter is the [SQLAlchemy](https://www.sqlalchemy.org) adapter for [PyCasbin](https://github.com/casbin/pycasbin). With this library, Casbin can load policy from SQLAlchemy supported database or save policy to it.

Based on [Officially Supported Databases](http://www.sqlalchemy.org/), The current supported databases are:

- PostgreSQL
- MySQL
- MariaDB
- SQLite
- Oracle
- Microsoft SQL Server
- Firebird

## Installation

```
pip install casbin_async_sqlalchemy_adapter
```

## Simple Example

```python
import casbin_async_sqlalchemy_adapter
import casbin

adapter = casbin_async_sqlalchemy_adapter.Adapter('sqlite+aiosqlite:///test.db')

# or mysql example 
# adapter = casbin_async_sqlalchemy_adapter.Adapter('mysql+aiomysql://user:pwd@127.0.0.1:3306/exampledb')

e = casbin.AsyncEnforcer('path/to/model.conf', adapter)

sub = "alice"  # the user that wants to access a resource.
obj = "data1"  # the resource that is going to be accessed.
act = "read"  # the operation that the user performs on the resource.

if e.enforce(sub, obj, act):
    # permit alice to read data1
    pass
else:
    # deny the request, show an error
    pass
```

> Note that AsyncAdaper must be used for AynscEnforcer.

## External Session Support

The adapter supports using externally managed SQLAlchemy sessions. This feature is useful for:

- Better transaction control in complex scenarios
- Reducing database connections and communications
- Supporting advanced database features like two-phase commits
- Integrating with existing database session management

### Basic Usage with External Session

```python
import casbin_async_sqlalchemy_adapter
import casbin
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker

# Create your own database session
engine = create_async_engine('sqlite+aiosqlite:///test.db')
async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

# Create adapter with external session
session = async_session()
adapter = casbin_async_sqlalchemy_adapter.Adapter(
    'sqlite+aiosqlite:///test.db',
    db_session=session
)

e = casbin.AsyncEnforcer('path/to/model.conf', adapter)

# Now you have full control over the session
# The adapter will not auto-commit or auto-rollback when using external sessions
```

### Transaction Control Example

```python
# Example: Manual transaction control
async with async_session() as session:
    adapter = casbin_async_sqlalchemy_adapter.Adapter(
        'sqlite+aiosqlite:///test.db',
        db_session=session
    )
    
    e = casbin.AsyncEnforcer('path/to/model.conf', adapter)
    
    # Add multiple policies in a single transaction
    await e.add_policy("alice", "data1", "read")
    await e.add_policy("bob", "data2", "write")
    
    # Commit or rollback as needed
    await session.commit()
```

### Batch Operations Example

```python
# Example: Efficient batch operations
async with async_session() as session:
    adapter = casbin_async_sqlalchemy_adapter.Adapter(
        'sqlite+aiosqlite:///test.db',
        db_session=session
    )
    
    e = casbin.AsyncEnforcer('path/to/model.conf', adapter)
    
    # Batch add multiple policies efficiently
    policies = [
        ["alice", "data1", "read"],
        ["bob", "data2", "write"],
        ["carol", "data3", "read"]
    ]
    await e.add_policies(policies)
    
    # Commit the transaction
    await session.commit()
```

## Soft Deletion Support

The adapter supports soft deletion, which marks records as deleted instead of physically removing them from the database. This is useful for:

- Maintaining audit trails
- Implementing undo functionality
- Preserving historical data
- Debugging and compliance requirements

### Basic Usage with Soft Deletion

To enable soft deletion, you need to:

1. Create a custom database model with a boolean `is_deleted` column
2. Pass the soft delete attribute to the adapter

```python
import casbin_async_sqlalchemy_adapter
import casbin
from sqlalchemy import Column, Boolean, Integer, String
from sqlalchemy.ext.asyncio import create_async_engine

# Define a custom model with soft delete support
class CasbinRuleSoftDelete(casbin_async_sqlalchemy_adapter.Base):
    __tablename__ = "casbin_rule"

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))
    
    # Add the soft delete column
    is_deleted = Column(Boolean, default=False, index=True, nullable=False)

# Create adapter with soft delete support
engine = create_async_engine('sqlite+aiosqlite:///test.db')
adapter = casbin_async_sqlalchemy_adapter.Adapter(
    engine,
    db_class=CasbinRuleSoftDelete,
    db_class_softdelete_attribute=CasbinRuleSoftDelete.is_deleted
)

# Create the table
await adapter.create_table()

e = casbin.AsyncEnforcer('path/to/model.conf', adapter)

# When you delete a policy, it will be soft-deleted (marked as deleted)
await e.delete_permission_for_user("alice", "data1", "read")

# The record remains in the database with is_deleted=True
# Load policy will automatically filter out soft-deleted records
await e.load_policy()
```

### How Soft Deletion Works

When soft deletion is enabled:

- **Delete operations** set the `is_deleted` flag to `True` instead of removing records
- **Load operations** automatically filter out records where `is_deleted=True`
- **Save policy** marks removed rules as deleted while preserving the records
- **Update operations** only affect non-deleted records

This feature maintains full backward compatibility - when `db_class_softdelete_attribute` is not provided, the adapter functions with hard deletion as before.

### Getting Help

- [PyCasbin](https://github.com/casbin/pycasbin)

### License

This project is licensed under the [Apache 2.0 license](LICENSE).
