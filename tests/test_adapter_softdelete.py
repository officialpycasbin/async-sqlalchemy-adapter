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
from pathlib import Path
from unittest import IsolatedAsyncioTestCase

import casbin
from sqlalchemy import Column, Boolean, Integer, String, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from casbin_async_sqlalchemy_adapter import Adapter
from casbin_async_sqlalchemy_adapter import Base
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


async def query_for_rule(session, adapter, ptype, v0, v1, v2):
    """Helper function to query for a specific rule."""
    rule_filter = Filter()
    rule_filter.ptype = [ptype]
    rule_filter.v0 = [v0]
    rule_filter.v1 = [v1]
    rule_filter.v2 = [v2]
    stmt = select(CasbinRuleSoftDelete)
    stmt = adapter.filter_query(stmt, rule_filter)
    result = await session.execute(stmt)
    return result.scalars().first()


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


class TestConfigSoftDelete(IsolatedAsyncioTestCase):
    async def get_enforcer(self):
        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        adapter = Adapter(engine, CasbinRuleSoftDelete, CasbinRuleSoftDelete.is_deleted)
        await adapter.create_table()

        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session() as s:
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
        """Test that custom database class with softdelete works."""
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

        session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with session() as s:
            s.add(CustomRule(not_exist="NotNone"))
            await s.commit()
            a = await s.execute(select(CustomRule))
            self.assertEqual(a.scalars().all()[0].not_exist, "NotNone")

    async def test_softdelete_flag(self):
        """Test that softdelete flag is set correctly when removing policies."""
        e = await self.get_enforcer()
        session_maker = e.adapter.session_local
        
        async with session_maker() as session:
            # Verify rule does not exist initially
            self.assertFalse(e.enforce("alice", "data5", "read"))
            rule = await query_for_rule(session, e.adapter, "p", "alice", "data5", "read")
            self.assertIsNone(rule)

        # Add new permission
        await e.add_permission_for_user("alice", "data5", "read")
        self.assertTrue(e.enforce("alice", "data5", "read"))
        
        async with session_maker() as session:
            rule = await query_for_rule(session, e.adapter, "p", "alice", "data5", "read")
            self.assertIsNotNone(rule)
            self.assertFalse(rule.is_deleted)

        # Delete permission - should soft delete
        await e.delete_permission_for_user("alice", "data5", "read")
        self.assertFalse(e.enforce("alice", "data5", "read"))
        
        async with session_maker() as session:
            rule = await query_for_rule(session, e.adapter, "p", "alice", "data5", "read")
            self.assertIsNotNone(rule)
            self.assertTrue(rule.is_deleted)

    async def test_save_policy_softdelete(self):
        """Test that save_policy correctly marks rules as deleted."""
        e = await self.get_enforcer()
        session_maker = e.adapter.session_local

        # Turn off auto save
        e.enable_auto_save(auto_save=False)

        # Delete some preexisting rules using model's internal methods
        e.get_model().remove_policy("p", "p", ["alice", "data1", "read"])
        e.get_model().remove_policy("p", "p", ["bob", "data2", "write"])
        # Delete a non existing rule (won't do anything in model)
        e.get_model().remove_policy("p", "p", ["bob", "data100", "read"])
        # Add some new rules using model's internal methods
        e.get_model().add_policy("p", "p", ["alice", "data100", "read"])
        e.get_model().add_policy("p", "p", ["bob", "data100", "write"])

        # Write changes to database
        await e.save_policy()

        async with session_maker() as session:
            # Check deleted rules are marked as deleted
            rule1 = await query_for_rule(session, e.adapter, "p", "alice", "data1", "read")
            self.assertTrue(rule1.is_deleted)
            
            rule2 = await query_for_rule(session, e.adapter, "p", "bob", "data2", "write")
            self.assertTrue(rule2.is_deleted)
            
            # Non-existent rule should not be in DB
            rule3 = await query_for_rule(session, e.adapter, "p", "bob", "data100", "read")
            self.assertIsNone(rule3)
            
            # New rules should not be deleted
            rule4 = await query_for_rule(session, e.adapter, "p", "alice", "data100", "read")
            self.assertIsNotNone(rule4)
            self.assertFalse(rule4.is_deleted)
            
            rule5 = await query_for_rule(session, e.adapter, "p", "bob", "data100", "write")
            self.assertIsNotNone(rule5)
            self.assertFalse(rule5.is_deleted)

    async def test_softdelete_type_validation(self):
        """Test that non-Boolean softdelete attribute raises ValueError."""
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
            is_deleted = Column(String(255))  # Wrong type!

        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        
        with self.assertRaises(ValueError) as context:
            Adapter(engine, InvalidRule, InvalidRule.is_deleted)
        
        self.assertIn("Boolean", str(context.exception))

    async def test_remove_policies_with_softdelete(self):
        """Test that remove_policies correctly soft-deletes multiple rules."""
        e = await self.get_enforcer()
        session_maker = e.adapter.session_local

        # Add multiple policies
        await e.add_policies([
            ["alice", "data10", "read"],
            ["bob", "data10", "write"],
            ["carol", "data10", "read"]
        ])

        # Verify they exist
        self.assertTrue(e.enforce("alice", "data10", "read"))
        self.assertTrue(e.enforce("bob", "data10", "write"))
        self.assertTrue(e.enforce("carol", "data10", "read"))

        # Remove multiple policies
        await e.remove_policies([
            ["alice", "data10", "read"],
            ["bob", "data10", "write"]
        ])

        # Verify they are soft-deleted
        self.assertFalse(e.enforce("alice", "data10", "read"))
        self.assertFalse(e.enforce("bob", "data10", "write"))
        self.assertTrue(e.enforce("carol", "data10", "read"))

        async with session_maker() as session:
            rule1 = await query_for_rule(session, e.adapter, "p", "alice", "data10", "read")
            self.assertIsNotNone(rule1)
            self.assertTrue(rule1.is_deleted)
            
            rule2 = await query_for_rule(session, e.adapter, "p", "bob", "data10", "write")
            self.assertIsNotNone(rule2)
            self.assertTrue(rule2.is_deleted)
            
            rule3 = await query_for_rule(session, e.adapter, "p", "carol", "data10", "read")
            self.assertIsNotNone(rule3)
            self.assertFalse(rule3.is_deleted)

    async def test_remove_filtered_policy_with_softdelete(self):
        """Test that remove_filtered_policy correctly soft-deletes matching rules."""
        e = await self.get_enforcer()
        session_maker = e.adapter.session_local

        # Initial state verification
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))

        # Remove all policies for data2 (field_index=1, value="data2")
        await e.remove_filtered_policy(1, "data2")

        # Verify policies are removed from enforcer
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))

        async with session_maker() as session:
            # All data2 policies should be soft-deleted
            rule1 = await query_for_rule(session, e.adapter, "p", "data2_admin", "data2", "read")
            self.assertIsNotNone(rule1)
            self.assertTrue(rule1.is_deleted)
            
            rule2 = await query_for_rule(session, e.adapter, "p", "data2_admin", "data2", "write")
            self.assertIsNotNone(rule2)
            self.assertTrue(rule2.is_deleted)

    async def test_update_policy_with_softdelete(self):
        """Test that update_policy works correctly with soft delete."""
        e = await self.get_enforcer()
        session_maker = e.adapter.session_local

        # Verify initial policy
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))

        # Update policy
        await e.update_policy(["alice", "data1", "read"], ["alice", "data1", "write"])

        # Verify updated policy
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data1", "write"))

        async with session_maker() as session:
            # The updated rule should not be deleted
            rule = await query_for_rule(session, e.adapter, "p", "alice", "data1", "write")
            self.assertIsNotNone(rule)
            self.assertFalse(rule.is_deleted)

    async def test_load_policy_ignores_soft_deleted(self):
        """Test that load_policy ignores soft-deleted rules."""
        e = await self.get_enforcer()
        session_maker = e.adapter.session_local

        # Delete a policy
        await e.delete_permission_for_user("alice", "data1", "read")
        
        async with session_maker() as session:
            rule = await query_for_rule(session, e.adapter, "p", "alice", "data1", "read")
            self.assertIsNotNone(rule)
            self.assertTrue(rule.is_deleted)

        # Create a new enforcer and load policy
        scriptdir = Path(os.path.dirname(os.path.realpath(__file__)))
        model_path = scriptdir / "rbac_model.conf"
        e2 = casbin.AsyncEnforcer(str(model_path), e.adapter)
        await e2.load_policy()

        # The soft-deleted policy should not be loaded
        self.assertFalse(e2.enforce("alice", "data1", "read"))
        # Other policies should still be loaded
        self.assertTrue(e2.enforce("bob", "data2", "write"))

    async def test_load_filtered_policy_ignores_soft_deleted(self):
        """Test that load_filtered_policy ignores soft-deleted rules."""
        e = await self.get_enforcer()
        
        # Delete a policy
        await e.delete_permission_for_user("bob", "data2", "write")

        # Create filter for data2
        filter = Filter()
        filter.v1 = ["data2"]

        # Create new enforcer with filtered policy
        scriptdir = Path(os.path.dirname(os.path.realpath(__file__)))
        model_path = scriptdir / "rbac_model.conf"
        e2 = casbin.AsyncEnforcer(str(model_path), e.adapter)
        await e2.load_filtered_policy(filter)

        # Soft-deleted policy should not be loaded
        self.assertFalse(e2.enforce("bob", "data2", "write"))
        # Other data2 policies should be loaded
        self.assertTrue(e2.enforce("data2_admin", "data2", "read"))
