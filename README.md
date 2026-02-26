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

> Note that AsyncAdapter must be used for AsyncEnforcer.

## Alembic Integration

For production applications, you'll want to manage database schema using Alembic migrations instead of calling `create_table()` at runtime. The adapter provides `create_casbin_rule_model()` to integrate with your existing migration workflow.

```python
# In your alembic/env.py or models file
from casbin_async_sqlalchemy_adapter import create_casbin_rule_model
from sqlalchemy.ext.declarative import declarative_base

# Use your application's declarative base
Base = declarative_base()

# Create the CasbinRule model using your base
CasbinRule = create_casbin_rule_model(Base)

# Now Alembic can auto-generate migrations for the casbin_rule table
# Run: alembic revision --autogenerate -m "Add casbin_rule table"
# Then: alembic upgrade head
```

When using the adapter with Alembic-managed tables, pass your custom model:

```python
from your_app.models import CasbinRule
import casbin_async_sqlalchemy_adapter
import casbin

adapter = casbin_async_sqlalchemy_adapter.Adapter(
    'sqlite+aiosqlite:///test.db',
    db_class=CasbinRule
)

e = casbin.AsyncEnforcer('path/to/model.conf', adapter)
```

## Atomic Transactions (Transaction Control)

The adapter lets you group multiple enforcer or adapter calls into a single atomic database transaction, so that either **all changes are committed together or none are**.

### Using `adapter.transaction()` — recommended for enforcer-level calls

The `transaction()` context manager binds a session to every adapter operation that happens inside the block.  You can obtain the adapter from an existing enforcer with `enforcer.get_adapter()`, so there is no need for a separate import or variable in most cases.

```python
import casbin
import casbin_async_sqlalchemy_adapter
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

engine = create_async_engine('sqlite+aiosqlite:///test.db')
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

adapter = casbin_async_sqlalchemy_adapter.Adapter(engine)
await adapter.create_table()

enforcer = casbin.AsyncEnforcer('path/to/model.conf', adapter)
await enforcer.load_policy()

# --- elsewhere in the application ---

# Obtain the adapter directly from the enforcer — no separate import needed.
adapter = enforcer.get_adapter()

async with async_session() as session:
    async with adapter.transaction(session=session):
        # All enforcer calls inside this block share `session` and do NOT
        # auto-commit — the adapter defers commit control to the caller.
        await enforcer.add_policy("alice", "data1", "read")
        await enforcer.add_policy("bob", "data2", "write")

    # Commit or roll back the entire batch atomically.
    await session.commit()       # persists both policies
    # await session.rollback()   # would discard both
```

#### Atomic user-creation example

```python
async def create_user(session, user_data):
    # Insert the user row – not yet committed.
    user = User(**user_data)
    session.add(user)
    await session.flush()        # get user.id without committing

    adapter = enforcer.get_adapter()
    async with adapter.transaction(session=session):
        await enforcer.add_role_for_user(str(user.id), "viewer")
        await enforcer.add_policy(str(user.id), "resource", "read")

    # One commit covers the user row AND all policy changes.
    await session.commit()
    # If anything raises before this point, session.rollback() leaves
    # the database in a clean state — no orphaned policies.
```

### Per-method `session` and `commit` parameters

For direct adapter calls you can pass `session` and `commit` keyword arguments individually:

```python
async with async_session() as session:
    await adapter.add_policy("p", "p", ["alice", "data1", "read"],
                             session=session, commit=False)
    await adapter.add_policies("p", "p", [["bob", "data2", "write"]],
                               session=session, commit=False)
    await session.commit()
```

All write methods accept these parameters: `add_policy`, `add_policies`, `remove_policy`, `remove_policies`, `remove_filtered_policy`, `update_policy`, `update_policies`, `update_filtered_policies`.

### Constructor-level external session (`db_session`)

The original constructor-level session is still supported for scenarios where every operation should share the same long-lived session:

```python
async with async_session() as session:
    adapter = casbin_async_sqlalchemy_adapter.Adapter(engine, db_session=session)
    e = casbin.AsyncEnforcer('path/to/model.conf', adapter)
    await e.load_policy()

    await e.add_policy("alice", "data1", "read")
    await e.add_policy("bob", "data2", "write")

    await session.commit()
```

## Clearing All Policies

The adapter provides a `clear_policy()` method to remove all policy records from the database directly:

```python
import casbin_async_sqlalchemy_adapter
import casbin
from sqlalchemy.ext.asyncio import create_async_engine

# Setup
engine = create_async_engine('sqlite+aiosqlite:///test.db')
adapter = casbin_async_sqlalchemy_adapter.Adapter(engine)
await adapter.create_table()

e = casbin.AsyncEnforcer('path/to/model.conf', adapter)
await e.load_policy()

# Add some policies
await e.add_policy("alice", "data1", "read")
await e.add_policy("bob", "data2", "write")

# Clear all policies from the database
await adapter.clear_policy()

# Reload to verify - the enforcer will have no policies
await e.load_policy()
```

When soft deletion is enabled, `clear_policy()` marks all records as deleted instead of physically removing them.

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
