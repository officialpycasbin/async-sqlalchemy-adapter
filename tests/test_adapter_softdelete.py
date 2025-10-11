# Copyright 2023 The casbin Authors. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import unittest
from unittest import IsolatedAsyncioTestCase
from pathlib import Path

import casbin
from sqlalchemy import Column, Integer, String, Boolean, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from casbin_async_sqlalchemy_adapter import Adapter, Base
from casbin_async_sqlalchemy_adapter.adapter import Filter


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

    is_deleted = Column(Boolean, default=False, index=True, nullable=False)

    def __str__(self):
        arr = [self.ptype]
        for v in (self.v0, self.v1, self.v2, self.v3, self.v4, self.v5):
            if v is None:
                break
            arr.append(v)
        return ", ".join(arr)

    def __repr__(self):
        return '<CasbinRule {}: "{}">'.format(self.id, str(self))


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


async def query_for_rule(session, adapter, ptype, v0, v1, v2):
    """Query for a specific rule in the database."""
    rule_filter = Filter()
    rule_filter.ptype = [ptype]
    rule_filter.v0 = [v0]
    rule_filter.v1 = [v1]
    rule_filter.v2 = [v2]
    
    stmt = select(CasbinRuleSoftDelete)
    stmt = adapter.filter_query(stmt, rule_filter)
    result = await session.execute(stmt)
    return result.scalars().all()


class TestConfigSoftDelete(IsolatedAsyncioTestCase):
    async def get_enforcer(self):
        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        adapter = Adapter(engine, CasbinRuleSoftDelete, CasbinRuleSoftDelete.is_deleted)
        
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session() as s:
            # Clear any existing data
            await s.execute(select(CasbinRuleSoftDelete))
            
            s.add(CasbinRuleSoftDelete(ptype="p", v0="alice", v1="data1", v2="read"))
            s.add(CasbinRuleSoftDelete(ptype="p", v0="bob", v1="data2", v2="write"))
            s.add(CasbinRuleSoftDelete(ptype="p", v0="data2_admin", v1="data2", v2="read"))
            s.add(CasbinRuleSoftDelete(ptype="p", v0="data2_admin", v1="data2", v2="write"))
            s.add(CasbinRuleSoftDelete(ptype="g", v0="alice", v1="data2_admin"))
            await s.commit()

        e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
        await e.load_policy()
        return e

    async def test_custom_db_class(self):
        """Test that custom db class with soft delete attribute works."""
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
        adapter = Adapter(engine, CustomRule, CustomRule.is_deleted)

        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session() as s:
            s.add(CustomRule(not_exist="NotNone"))
            await s.commit()
            result = await s.execute(select(CustomRule))
            self.assertEqual(result.scalars().all()[0].not_exist, "NotNone")

    async def test_softdelete_flag(self):
        """Test that soft delete flag is set when removing a policy."""
        e = await self.get_enforcer()
        engine = e.get_adapter()._engine
        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        async with async_session() as session:
            # Initially, rule doesn't exist
            query_result = await query_for_rule(session, e.get_adapter(), "p", "alice", "data5", "read")
            self.assertFalse(e.enforce("alice", "data5", "read"))
            self.assertEqual(len(query_result), 0)

            # Add the rule
            await e.add_permission_for_user("alice", "data5", "read")
            await session.commit()

        async with async_session() as session:
            # Rule exists and is not deleted
            query_result = await query_for_rule(session, e.get_adapter(), "p", "alice", "data5", "read")
            self.assertTrue(e.enforce("alice", "data5", "read"))
            self.assertEqual(len(query_result), 1)
            self.assertFalse(query_result[0].is_deleted)

            # Remove the rule (soft delete)
            await e.delete_permission_for_user("alice", "data5", "read")
            await session.commit()

        async with async_session() as session:
            # Rule still exists in DB but is marked as deleted
            stmt = select(CasbinRuleSoftDelete).where(
                CasbinRuleSoftDelete.ptype == "p",
                CasbinRuleSoftDelete.v0 == "alice",
                CasbinRuleSoftDelete.v1 == "data5",
                CasbinRuleSoftDelete.v2 == "read"
            )
            result = await session.execute(stmt)
            all_results = result.scalars().all()
            self.assertFalse(e.enforce("alice", "data5", "read"))
            self.assertEqual(len(all_results), 1)
            self.assertTrue(all_results[0].is_deleted)

    async def test_save_policy_softdelete(self):
        """Test that save_policy handles soft delete correctly."""
        e = await self.get_enforcer()
        engine = e.get_adapter()._engine
        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        # Turn off auto save
        e.enable_auto_save(auto_save=False)

        # Get model and manipulate policies directly
        model = e.get_model()
        
        # Delete some preexisting rules from model (not from DB yet)
        model.remove_policy("p", "p", ["alice", "data1", "read"])
        model.remove_policy("p", "p", ["bob", "data2", "write"])
        
        # Add some new rules to model (not in DB yet)
        model.add_policy("p", "p", ["alice", "data100", "read"])
        model.add_policy("p", "p", ["bob", "data100", "write"])

        # Write changes to database - this should soft-delete removed rules
        await e.save_policy()

        async with async_session() as session:
            # Check that deleted rules are marked as deleted
            stmt1 = select(CasbinRuleSoftDelete).where(
                CasbinRuleSoftDelete.ptype == "p",
                CasbinRuleSoftDelete.v0 == "alice",
                CasbinRuleSoftDelete.v1 == "data1",
                CasbinRuleSoftDelete.v2 == "read"
            )
            result1 = await session.execute(stmt1)
            alice_data1 = result1.scalars().first()
            self.assertIsNotNone(alice_data1)
            self.assertTrue(alice_data1.is_deleted)

            stmt2 = select(CasbinRuleSoftDelete).where(
                CasbinRuleSoftDelete.ptype == "p",
                CasbinRuleSoftDelete.v0 == "bob",
                CasbinRuleSoftDelete.v1 == "data2",
                CasbinRuleSoftDelete.v2 == "write"
            )
            result2 = await session.execute(stmt2)
            bob_data2 = result2.scalars().first()
            self.assertIsNotNone(bob_data2)
            self.assertTrue(bob_data2.is_deleted)

            # Check that new rules are not deleted
            stmt4 = select(CasbinRuleSoftDelete).where(
                CasbinRuleSoftDelete.ptype == "p",
                CasbinRuleSoftDelete.v0 == "alice",
                CasbinRuleSoftDelete.v1 == "data100",
                CasbinRuleSoftDelete.v2 == "read"
            )
            result4 = await session.execute(stmt4)
            alice_data100 = result4.scalars().first()
            self.assertIsNotNone(alice_data100)
            self.assertFalse(alice_data100.is_deleted)

            stmt5 = select(CasbinRuleSoftDelete).where(
                CasbinRuleSoftDelete.ptype == "p",
                CasbinRuleSoftDelete.v0 == "bob",
                CasbinRuleSoftDelete.v1 == "data100",
                CasbinRuleSoftDelete.v2 == "write"
            )
            result5 = await session.execute(stmt5)
            bob_data100 = result5.scalars().first()
            self.assertIsNotNone(bob_data100)
            self.assertFalse(bob_data100.is_deleted)

    async def test_enforcer_basic(self):
        """Test that basic enforcement works with soft delete."""
        e = await self.get_enforcer()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_remove_policies_softdelete(self):
        """Test that remove_policies works with soft delete."""
        e = await self.get_enforcer()
        engine = e.get_adapter()._engine
        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertFalse(e.enforce("alice", "data6", "read"))
        await e.add_policies((("alice", "data5", "read"), ("alice", "data6", "read")))
        self.assertTrue(e.enforce("alice", "data5", "read"))
        self.assertTrue(e.enforce("alice", "data6", "read"))
        
        await e.remove_policies((("alice", "data5", "read"), ("alice", "data6", "read")))
        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertFalse(e.enforce("alice", "data6", "read"))

        # Verify soft deletion
        async with async_session() as session:
            stmt = select(CasbinRuleSoftDelete).where(
                CasbinRuleSoftDelete.ptype == "p",
                CasbinRuleSoftDelete.v0 == "alice"
            )
            result = await session.execute(stmt)
            all_alice_rules = result.scalars().all()
            
            # Find the soft-deleted rules
            deleted_rules = [r for r in all_alice_rules if r.v1 in ["data5", "data6"] and r.is_deleted]
            self.assertEqual(len(deleted_rules), 2)

    async def test_remove_filtered_policy_softdelete(self):
        """Test that remove_filtered_policy works with soft delete."""
        e = await self.get_enforcer()
        engine = e.get_adapter()._engine
        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        self.assertTrue(e.enforce("alice", "data1", "read"))
        await e.remove_filtered_policy(1, "data1")
        self.assertFalse(e.enforce("alice", "data1", "read"))

        # Verify soft deletion
        async with async_session() as session:
            stmt = select(CasbinRuleSoftDelete).where(
                CasbinRuleSoftDelete.ptype == "p",
                CasbinRuleSoftDelete.v1 == "data1"
            )
            result = await session.execute(stmt)
            data1_rules = result.scalars().all()
            self.assertTrue(all(r.is_deleted for r in data1_rules))

    async def test_invalid_softdelete_attribute_type(self):
        """Test that invalid soft delete attribute type raises ValueError."""
        class InvalidRule(Base):
            __tablename__ = "invalid_rule"

            id = Column(Integer, primary_key=True)
            ptype = Column(String(255))
            v0 = Column(String(255))
            v1 = Column(String(255))
            v2 = Column(String(255))
            v3 = Column(String(255))
            v4 = Column(String(255))
            v5 = Column(String(255))
            is_deleted = Column(String(255))  # Wrong type - should be Boolean

        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        
        with self.assertRaises(ValueError) as context:
            adapter = Adapter(engine, InvalidRule, InvalidRule.is_deleted)
        
        self.assertIn("Boolean", str(context.exception))


if __name__ == "__main__":
    unittest.main()
