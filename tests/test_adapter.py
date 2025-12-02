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

import casbin
from sqlalchemy import Column, Integer, String, select
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

from casbin_async_sqlalchemy_adapter import Adapter
from casbin_async_sqlalchemy_adapter import Base
from casbin_async_sqlalchemy_adapter import CasbinRule
from casbin_async_sqlalchemy_adapter import create_casbin_rule_model
from casbin_async_sqlalchemy_adapter.adapter import Filter


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


async def get_enforcer():
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    # engine = create_async_engine('sqlite+aiosqlite:///' + os.path.split(os.path.realpath(__file__))[0] + '/test.db',
    # echo=True)
    adapter = Adapter(engine)
    await adapter.create_table()

    async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    async with async_session() as s:
        s.add(CasbinRule(ptype="p", v0="alice", v1="data1", v2="read"))
        s.add(CasbinRule(ptype="p", v0="bob", v1="data2", v2="write"))
        s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read"))
        s.add(CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write"))
        s.add(CasbinRule(ptype="g", v0="alice", v1="data2_admin"))
        await s.commit()

    e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
    await e.load_policy()
    return e


class TestConfig(IsolatedAsyncioTestCase):
    async def test_custom_db_class(self):
        class CustomRule(Base):
            __tablename__ = "casbin_rule2"

            id = Column(Integer, primary_key=True)
            ptype = Column(String(255))
            v0 = Column(String(255))
            v1 = Column(String(255))
            v2 = Column(String(255))
            v3 = Column(String(255))
            v4 = Column(String(255))
            v5 = Column(String(255))
            not_exist = Column(String(255))

        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with session() as s:
            s.add(CustomRule(not_exist="NotNone"))
            await s.commit()
            a = await s.execute(select(CustomRule))
            self.assertEqual(a.scalars().all()[0].not_exist, "NotNone")

    async def test_enforcer_basic(self):
        e = await get_enforcer()
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

    async def test_add_policy(self):
        e = await get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        res = await e.add_policies((("eve", "data3", "read"), ("eve", "data4", "read")))
        self.assertTrue(res)
        self.assertTrue(e.enforce("eve", "data3", "read"))
        self.assertTrue(e.enforce("eve", "data4", "read"))

    async def test_add_policies(self):
        e = await get_enforcer()

        self.assertFalse(e.enforce("eve", "data3", "read"))
        res = await e.add_permission_for_user("eve", "data3", "read")
        self.assertTrue(res)
        self.assertTrue(e.enforce("eve", "data3", "read"))

    async def test_save_policy(self):
        e = await get_enforcer()
        self.assertFalse(e.enforce("alice", "data4", "read"))

        model = e.get_model()
        model.clear_policy()

        model.add_policy("p", "p", ["alice", "data4", "read"])

        adapter = e.get_adapter()
        await adapter.save_policy(model)
        self.assertTrue(e.enforce("alice", "data4", "read"))

    async def test_remove_policy(self):
        e = await get_enforcer()

        self.assertFalse(e.enforce("alice", "data5", "read"))
        await e.add_permission_for_user("alice", "data5", "read")
        self.assertTrue(e.enforce("alice", "data5", "read"))
        await e.delete_permission_for_user("alice", "data5", "read")
        self.assertFalse(e.enforce("alice", "data5", "read"))

    async def test_remove_policies(self):
        e = await get_enforcer()

        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertFalse(e.enforce("alice", "data6", "read"))
        await e.add_policies((("alice", "data5", "read"), ("alice", "data6", "read")))
        self.assertTrue(e.enforce("alice", "data5", "read"))
        self.assertTrue(e.enforce("alice", "data6", "read"))
        await e.remove_policies((("alice", "data5", "read"), ("alice", "data6", "read")))
        self.assertFalse(e.enforce("alice", "data5", "read"))
        self.assertFalse(e.enforce("alice", "data6", "read"))

    async def test_remove_filtered_policy(self):
        e = await get_enforcer()

        self.assertTrue(e.enforce("alice", "data1", "read"))
        await e.remove_filtered_policy(1, "data1")
        self.assertFalse(e.enforce("alice", "data1", "read"))

        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        await e.remove_filtered_policy(1, "data2", "read")

        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertTrue(e.enforce("alice", "data2", "write"))

        await e.remove_filtered_policy(2, "write")

        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("alice", "data2", "write"))

    async def test_str(self):
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(str(rule), "p, alice, data1, read")
        rule = CasbinRule(ptype="p", v0="bob", v1="data2", v2="write")
        self.assertEqual(str(rule), "p, bob, data2, write")
        rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="read")
        self.assertEqual(str(rule), "p, data2_admin, data2, read")
        rule = CasbinRule(ptype="p", v0="data2_admin", v1="data2", v2="write")
        self.assertEqual(str(rule), "p, data2_admin, data2, write")
        rule = CasbinRule(ptype="g", v0="alice", v1="data2_admin")
        self.assertEqual(str(rule), "g, alice, data2_admin")

    async def test_repr(self):
        rule = CasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(repr(rule), '<CasbinRule None: "p, alice, data1, read">')
        engine = create_async_engine("sqlite+aiosqlite://", future=True)

        session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        s = session()

        s.add(rule)
        await s.commit()
        self.assertRegex(repr(rule), r'<CasbinRule \d+: "p, alice, data1, read">')
        await s.close()

    async def test_filtered_policy(self):
        e = await get_enforcer()
        filter = Filter()

        filter.ptype = ["p"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))

        filter.ptype = []
        filter.v0 = ["alice"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = ["bob"]
        await e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = ["data2_admin"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))

        filter.v0 = ["alice", "bob"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v0 = []
        filter.v1 = ["data1"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v1 = ["data2"]
        await e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "write"))

        filter.v1 = []
        filter.v2 = ["read"]
        await e.load_filtered_policy(filter)
        self.assertTrue(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data2", "read"))
        self.assertFalse(e.enforce("data2_admin", "data2", "write"))

        filter.v2 = ["write"]
        await e.load_filtered_policy(filter)
        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertFalse(e.enforce("alice", "data1", "write"))
        self.assertFalse(e.enforce("alice", "data2", "read"))
        self.assertFalse(e.enforce("alice", "data2", "write"))
        self.assertFalse(e.enforce("bob", "data1", "read"))
        self.assertFalse(e.enforce("bob", "data1", "write"))
        self.assertFalse(e.enforce("bob", "data2", "read"))
        self.assertTrue(e.enforce("bob", "data2", "write"))
        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data2", "write"))

    async def test_update_policy(self):
        e = await get_enforcer()
        example_p = ["mike", "cookie", "eat"]

        self.assertTrue(e.enforce("alice", "data1", "read"))
        await e.update_policy(["alice", "data1", "read"], ["alice", "data1", "no_read"])
        self.assertFalse(e.enforce("alice", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "read"))
        await e.add_policy(example_p)
        await e.update_policy(example_p, ["bob", "data1", "read"])
        self.assertTrue(e.enforce("bob", "data1", "read"))

        self.assertFalse(e.enforce("bob", "data1", "write"))
        await e.update_policy(["bob", "data1", "read"], ["bob", "data1", "write"])
        self.assertTrue(e.enforce("bob", "data1", "write"))

        self.assertTrue(e.enforce("bob", "data2", "write"))
        await e.update_policy(["bob", "data2", "write"], ["bob", "data2", "read"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("bob", "data2", "read"))
        await e.update_policy(["bob", "data2", "read"], ["carl", "data2", "write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

        self.assertTrue(e.enforce("carl", "data2", "write"))
        await e.update_policy(["carl", "data2", "write"], ["carl", "data2", "no_write"])
        self.assertFalse(e.enforce("bob", "data2", "write"))

    async def test_update_policies(self):
        e = await get_enforcer()

        old_rule_0 = ["alice", "data1", "read"]
        old_rule_1 = ["bob", "data2", "write"]
        old_rule_2 = ["data2_admin", "data2", "read"]
        old_rule_3 = ["data2_admin", "data2", "write"]

        new_rule_0 = ["alice", "data_test", "read"]
        new_rule_1 = ["bob", "data_test", "write"]
        new_rule_2 = ["data2_admin", "data_test", "read"]
        new_rule_3 = ["data2_admin", "data_test", "write"]

        old_rules = [old_rule_0, old_rule_1, old_rule_2, old_rule_3]
        new_rules = [new_rule_0, new_rule_1, new_rule_2, new_rule_3]

        await e.update_policies(old_rules, new_rules)

        self.assertFalse(e.enforce("alice", "data1", "read"))
        self.assertTrue(e.enforce("alice", "data_test", "read"))

        self.assertFalse(e.enforce("bob", "data2", "write"))
        self.assertTrue(e.enforce("bob", "data_test", "write"))

        self.assertFalse(e.enforce("data2_admin", "data2", "read"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "read"))

        self.assertFalse(e.enforce("data2_admin", "data2", "write"))
        self.assertTrue(e.enforce("data2_admin", "data_test", "write"))

    async def test_update_filtered_policies(self):
        e = await get_enforcer()

        await e.update_filtered_policies(
            [
                ["data2_admin", "data3", "read"],
                ["data2_admin", "data3", "write"],
            ],
            0,
            "data2_admin",
        )
        self.assertTrue(e.enforce("data2_admin", "data3", "write"))
        self.assertTrue(e.enforce("data2_admin", "data3", "read"))

        await e.update_filtered_policies([["alice", "data1", "write"]], 0, "alice")
        self.assertTrue(e.enforce("alice", "data1", "write"))

        await e.update_filtered_policies([["bob", "data2", "read"]], 0, "bob")
        self.assertTrue(e.enforce("bob", "data2", "read"))


class TestBulkInsert(IsolatedAsyncioTestCase):
    async def test_add_policies_bulk_internal_session(self):
        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        adapter = Adapter(engine)
        await adapter.create_table()

        rules = [
            ("u1", "obj1", "read"),
            ("u2", "obj2", "write"),
            ("u3", "obj3", "read"),
        ]
        await adapter.add_policies("p", "p", rules)

        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session() as s:
            # count inserted rows
            from sqlalchemy import select, func

            cnt = await s.execute(select(func.count()).select_from(CasbinRule).where(CasbinRule.ptype == "p"))
            assert cnt.scalar_one() == len(rules)

            rows = (await s.execute(select(CasbinRule).order_by(CasbinRule.id))).scalars().all()
            tuples = [(r.v0, r.v1, r.v2) for r in rows]
            for r in rules:
                assert r in tuples


class TestCreateCasbinRuleModel(IsolatedAsyncioTestCase):
    async def test_create_casbin_rule_model_with_custom_base(self):
        """Test that create_casbin_rule_model creates a model with the given base's metadata."""
        # Create a custom Base (simulating user's application Base)
        CustomBase = declarative_base()

        # Use a unique table name to avoid conflicts with other tests
        CustomCasbinRule = create_casbin_rule_model(CustomBase, table_name="test_custom_rule")

        # Verify the model uses the custom Base's metadata
        self.assertIn("test_custom_rule", CustomBase.metadata.tables)

        # Verify the model has all required columns
        self.assertTrue(hasattr(CustomCasbinRule, "id"))
        self.assertTrue(hasattr(CustomCasbinRule, "ptype"))
        self.assertTrue(hasattr(CustomCasbinRule, "v0"))
        self.assertTrue(hasattr(CustomCasbinRule, "v1"))
        self.assertTrue(hasattr(CustomCasbinRule, "v2"))
        self.assertTrue(hasattr(CustomCasbinRule, "v3"))
        self.assertTrue(hasattr(CustomCasbinRule, "v4"))
        self.assertTrue(hasattr(CustomCasbinRule, "v5"))

        # Create engine and table
        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        async with engine.begin() as conn:
            await conn.run_sync(CustomBase.metadata.create_all)

        # Test that we can insert and query records
        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session() as s:
            s.add(CustomCasbinRule(ptype="p", v0="alice", v1="data1", v2="read"))
            await s.commit()
            result = await s.execute(select(CustomCasbinRule))
            rules = result.scalars().all()
            self.assertEqual(len(rules), 1)
            self.assertEqual(str(rules[0]), "p, alice, data1, read")

    async def test_create_casbin_rule_model_with_custom_table_name(self):
        """Test that create_casbin_rule_model respects custom table name."""
        CustomBase = declarative_base()
        CustomCasbinRule = create_casbin_rule_model(CustomBase, table_name="my_custom_rules")

        self.assertIn("my_custom_rules", CustomBase.metadata.tables)
        self.assertEqual(CustomCasbinRule.__tablename__, "my_custom_rules")

    async def test_create_casbin_rule_model_str_and_repr(self):
        """Test that str and repr methods work correctly on the created model."""
        CustomBase = declarative_base()
        CustomCasbinRule = create_casbin_rule_model(CustomBase, table_name="str_repr_test_rules")

        rule = CustomCasbinRule(ptype="p", v0="alice", v1="data1", v2="read")
        self.assertEqual(str(rule), "p, alice, data1, read")
        self.assertEqual(repr(rule), '<CasbinRule None: "p, alice, data1, read">')

    async def test_create_casbin_rule_model_with_adapter(self):
        """Test that the created model works with the Adapter (uses adapter's Base to avoid side effects)."""
        # Use the adapter's Base to create the rule model - this avoids the side effect
        # of Base.metadata = db_class.metadata in the Adapter constructor
        CustomCasbinRule = create_casbin_rule_model(Base, table_name="adapter_test_rule")

        # Verify the model uses Base's metadata
        self.assertIn("adapter_test_rule", Base.metadata.tables)

        # Create engine and table
        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        await Adapter(engine, db_class=CustomCasbinRule).create_table()

        async_session = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
        async with async_session() as s:
            s.add(CustomCasbinRule(ptype="p", v0="bob", v1="data2", v2="write"))
            await s.commit()

        # Test that the model works with the Adapter
        adapter = Adapter(engine, db_class=CustomCasbinRule)
        e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
        await e.load_policy()
        self.assertTrue(e.enforce("bob", "data2", "write"))


if __name__ == "__main__":
    unittest.main()
