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

"""Unit tests for Adapter.use_session(), i.e. per-call transaction control."""

import asyncio
import os
import unittest
from unittest import IsolatedAsyncioTestCase

import casbin
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from casbin_async_sqlalchemy_adapter import Adapter, CasbinRule


def get_fixture(path):
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


async def get_enforcer_and_session_factory():
    """A long-lived adapter/enforcer, like an app would keep as a singleton."""
    engine = create_async_engine("sqlite+aiosqlite://", future=True)
    adapter = Adapter(engine)
    await adapter.create_table()

    e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
    await e.load_policy()

    session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
    return e, adapter, session_factory


async def count_rules(session_factory):
    async with session_factory() as session:
        result = await session.execute(select(func.count()).select_from(CasbinRule))
        return result.scalar()


class TestUseSession(IsolatedAsyncioTestCase):
    async def test_rollback_discards_policy_changes(self):
        e, adapter, session_factory = await get_enforcer_and_session_factory()

        async with session_factory() as session:
            async with adapter.use_session(session):
                await e.add_policy("alice", "data1", "read")
                await e.add_grouping_policy("alice", "data2_admin")
            await session.rollback()

        self.assertEqual(0, await count_rules(session_factory))

    async def test_commit_persists_policy_changes(self):
        e, adapter, session_factory = await get_enforcer_and_session_factory()

        async with session_factory() as session:
            async with adapter.use_session(session):
                await e.add_policy("alice", "data1", "read")
                await e.add_policies([["bob", "data2", "write"], ["carol", "data3", "read"]])
            await session.commit()

        self.assertEqual(3, await count_rules(session_factory))

        # A brand-new enforcer sees the committed rules.
        new_enforcer = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
        await new_enforcer.load_policy()
        self.assertTrue(new_enforcer.enforce("alice", "data1", "read"))
        self.assertTrue(new_enforcer.enforce("bob", "data2", "write"))

    async def test_binding_is_released_after_block(self):
        e, adapter, session_factory = await get_enforcer_and_session_factory()

        async with session_factory() as session:
            async with adapter.use_session(session):
                await e.add_policy("alice", "data1", "read")
            await session.rollback()

        self.assertIsNone(adapter._current_external_session())

        # Back to the default behaviour: the adapter opens and commits its own session.
        await e.add_policy("bob", "data2", "write")
        self.assertEqual(1, await count_rules(session_factory))

    async def test_removal_participates_in_the_transaction(self):
        e, adapter, session_factory = await get_enforcer_and_session_factory()

        await e.add_policies([["alice", "data1", "read"], ["bob", "data2", "write"]])
        self.assertEqual(2, await count_rules(session_factory))

        async with session_factory() as session:
            async with adapter.use_session(session):
                await e.remove_policy("alice", "data1", "read")
                await e.remove_filtered_policy(0, "bob")
            await session.rollback()

        self.assertEqual(2, await count_rules(session_factory))

    async def test_update_policies_is_a_single_transaction(self):
        e, adapter, session_factory = await get_enforcer_and_session_factory()

        await e.add_policies([["alice", "data1", "read"], ["bob", "data2", "write"]])

        async with session_factory() as session:
            async with adapter.use_session(session):
                await e.update_policies(
                    [["alice", "data1", "read"], ["bob", "data2", "write"]],
                    [["alice", "data1", "write"], ["bob", "data2", "read"]],
                )
            await session.rollback()

        new_enforcer = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
        await new_enforcer.load_policy()
        self.assertTrue(new_enforcer.enforce("alice", "data1", "read"))
        self.assertFalse(new_enforcer.enforce("alice", "data1", "write"))

    async def test_binding_does_not_leak_into_other_tasks(self):
        _, adapter, session_factory = await get_enforcer_and_session_factory()
        seen_by_other_task = []
        bound = asyncio.Event()
        checked = asyncio.Event()

        async def other_task():
            await bound.wait()
            seen_by_other_task.append(adapter._current_external_session())
            checked.set()

        task = asyncio.create_task(other_task())
        async with session_factory() as session:
            async with adapter.use_session(session):
                bound.set()
                await checked.wait()
        await task

        self.assertEqual([None], seen_by_other_task)

    async def test_constructor_session_still_works(self):
        """db_session= passed to the constructor keeps its previous behaviour."""
        engine = create_async_engine("sqlite+aiosqlite://", future=True)
        session_factory = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

        async with session_factory() as session:
            adapter = Adapter(engine, db_session=session)
            await adapter.create_table()
            e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
            await e.load_policy()

            await e.add_policy("alice", "data1", "read")
            await session.rollback()

        self.assertEqual(0, await count_rules(session_factory))


if __name__ == "__main__":
    unittest.main()
