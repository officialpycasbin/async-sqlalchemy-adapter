import os
from pathlib import Path

import casbin
from sqlalchemy import Column, Boolean, Integer, String, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from casbin_async_sqlalchemy_adapter import Adapter
from casbin_async_sqlalchemy_adapter import Base
from casbin_async_sqlalchemy_adapter.adapter import Filter
from casbin_async_sqlalchemy_adapter import CasbinRule

from tests.test_adapter import TestConfig


class CasbinRuleSoftDelete(Base):
    __tablename__ = "casbin_rule_soft_delete"

    id = Column(Integer, primary_key=True)
    ptype = Column(String(255))
    v0 = Column(String(255))
    v1 = Column(String(255))
    v2 = Column(String(255))
    v3 = Column(String(255))
    v4 = Column(String(255))
    v5 = Column(String(255))

    is_deleted = Column(Boolean, default=False, nullable=False)

    def __str__(self):
        arr = [self.ptype]
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self):
        return '<CasbinRule {}: "{}">'.format(self.id, str(self))


def query_for_rule(adaper, ptype, v0, v1, v2):
    rule_filter = Filter()
    rule_filter.ptype = [ptype]
    rule_filter.v0 = [v0]
    rule_filter.v1 = [v1]
    rule_filter.v2 = [v2]

    stmt = select(CasbinRuleSoftDelete)
    stmt = adaper.filter_query(stmt, rule_filter)
    return stmt


class TestConfigSoftDelete(TestConfig):
    def setUp(self):
        """ensure a clean state by deleting the old database file"""
        db_file = "./test.db"
        if os.path.exists(db_file):
            os.remove(db_file)

    def tearDown(self):
        """clean up by deleting the database file"""
        db_file = "./test.db"
        if os.path.exists(db_file):
            os.remove(db_file)

    async def get_enforcer(self):
        engine = create_async_engine("sqlite+aiosqlite:///./test.db", future=True)
        adapter = Adapter(engine, db_class=CasbinRuleSoftDelete, soft_delete=CasbinRuleSoftDelete.is_deleted)
        await adapter.create_table()

        async_session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session_maker() as s:
            s.add(CasbinRuleSoftDelete(ptype="p", v0="alice", v1="data1", v2="read"))
            s.add(CasbinRuleSoftDelete(ptype="p", v0="bob", v1="data2", v2="write"))
            s.add(CasbinRuleSoftDelete(ptype="p", v0="data2_admin", v1="data2", v2="read"))
            s.add(CasbinRuleSoftDelete(ptype="p", v0="data2_admin", v1="data2", v2="write"))
            s.add(CasbinRuleSoftDelete(ptype="g", v0="alice", v1="data2_admin"))
            await s.commit()

        scriptdir = Path(os.path.dirname(os.path.realpath(__file__)))
        model_path = scriptdir / "rbac_model.conf"
        e = casbin.AsyncEnforcer(str(model_path), adapter)
        await e.load_policy()

        return e

    async def test_custom_db_class(self):
        class CustomRule(Base):
            __tablename__ = "casbin_rule3"
            __table_args__ = {"extend_existing": True}

            id = Column(Integer, primary_key=True)
            ptype = Column(String(255))
            v0 = Column(String(255))
            v1 = Column(String(255))
            v2 = Column(String(255))
            v3 = Column(String(255))
            v4 = Column(String(255))
            v5 = Column(String(255))
            is_deleted = Column(Boolean, default=False)
            not_exist = Column(String(255))

        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async_session_maker = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session_maker() as s:
            s.add(CustomRule(not_exist="NotNone"))
            await s.commit()
            a = await s.execute(select(CustomRule))
            self.assertEqual(a.scalars().all()[0].not_exist, "NotNone")

    async def test_softdelete_flag(self):
        e = await self.get_enforcer()
        async_session_maker = e.adapter.session_local

        self.assertFalse(e.enforce("alice", "data5", "read"))

        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "alice", "data5", "read")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNone(rule)

        await e.add_permission_for_user("alice", "data5", "read")
        self.assertTrue(e.enforce("alice", "data5", "read"))
        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "alice", "data5", "read")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNotNone(rule)
            self.assertFalse(rule.is_deleted)

        await e.delete_permission_for_user("alice", "data5", "read")
        self.assertFalse(e.enforce("alice", "data5", "read"))
        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "alice", "data5", "read")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNotNone(rule)
            self.assertTrue(rule.is_deleted)

    async def test_save_policy_softdelete(self):
        e = await self.get_enforcer()
        async_session_maker = e.adapter.session_local

        # Turn off auto save
        e.enable_auto_save(auto_save=False)

        # Delete some preexisting rules
        await e.delete_permission_for_user("alice", "data1", "read")
        await e.delete_permission_for_user("bob", "data2", "write")
        # Delete a non existing rule
        await e.delete_permission_for_user("bob", "data100", "read")
        # Add some new rules
        await e.add_permission_for_user("alice", "data100", "read")
        await e.add_permission_for_user("bob", "data100", "write")

        # Write changes to database
        await e.save_policy()

        # Check1: ("alice", "data1", "read") should be marked as deleted
        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "alice", "data1", "read")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNotNone(rule)
            self.assertTrue(rule.is_deleted)

        # Check2: ("bob", "data2", "write") should be marked as deleted
        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "bob", "data2", "write")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNotNone(rule)
            self.assertTrue(rule.is_deleted)

        # Check3: ("bob", "data100", "read") should not exist
        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "bob", "data100", "read")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNone(rule)

        # Check4: ("alice", "data100", "read") should exist and not be deleted
        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "alice", "data100", "read")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNotNone(rule)
            self.assertFalse(rule.is_deleted)

        # Check5: ("bob", "data100", "write") should exist and not be deleted
        async with async_session_maker() as session:
            stmt = query_for_rule(e.adapter, "p", "bob", "data100", "write")
            result = await session.execute(stmt)
            rule = result.scalars().first()
            self.assertIsNotNone(rule)
            self.assertFalse(rule.is_deleted)
