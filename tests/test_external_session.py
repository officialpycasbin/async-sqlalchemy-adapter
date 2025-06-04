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


"""
Unit tests for external session functionality.
"""

import os
import tempfile
import unittest
from unittest import IsolatedAsyncioTestCase

import casbin
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

from casbin_async_sqlalchemy_adapter import Adapter
from casbin_async_sqlalchemy_adapter import CasbinRule


def get_fixture(path):
    """Get fixture file path."""
    dir_path = os.path.split(os.path.realpath(__file__))[0] + "/"
    return os.path.abspath(dir_path + path)


class TestExternalSession(IsolatedAsyncioTestCase):
    """Test external session functionality."""

    async def test_external_session_commit(self):
        """Test using external session with commit."""
        # Create a temporary database file
        db_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        db_file.close()
        
        try:
            # Create async engine
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_file.name}", future=True)
            
            # Create session factory
            async_session_factory = async_sessionmaker(engine, expire_on_commit=False)
            
            # Test with external session
            async with async_session_factory() as external_session:
                # Create adapter with external session
                adapter = Adapter(engine, db_session=external_session)
                
                # Create table
                await adapter.create_table()
                
                # Create enforcer
                e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
                await e.load_policy()
                
                # Add permissions
                await e.add_permission_for_user('alice', 'data1', 'read')
                await e.add_permission_for_user('alice', 'data2', 'read')
                
                # Verify permissions are available in current session
                self.assertTrue(e.enforce('alice', 'data1', 'read'))
                self.assertTrue(e.enforce('alice', 'data2', 'read'))
                
                # Commit the transaction
                await external_session.commit()
            
            # Verify permissions persist after commit with new session
            async with async_session_factory() as new_session:
                new_adapter = Adapter(engine, db_session=new_session)
                new_enforcer = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), new_adapter)
                await new_enforcer.load_policy()
                
                self.assertTrue(new_enforcer.enforce('alice', 'data1', 'read'))
                self.assertTrue(new_enforcer.enforce('alice', 'data2', 'read'))
        
        finally:
            # Clean up
            if os.path.exists(db_file.name):
                os.unlink(db_file.name)

    async def test_external_session_rollback(self):
        """Test using external session with rollback."""
        # Create a temporary database file
        db_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        db_file.close()
        
        try:
            # Create async engine
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_file.name}", future=True)
            
            # Create session factory
            async_session_factory = async_sessionmaker(engine, expire_on_commit=False)
            
            # Test with external session
            async with async_session_factory() as external_session:
                # Create adapter with external session
                adapter = Adapter(engine, db_session=external_session)
                
                # Create table
                await adapter.create_table()
                
                # Create enforcer
                e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
                await e.load_policy()
                
                # Add permissions
                await e.add_permission_for_user('alice', 'data1', 'read')
                await e.add_permission_for_user('alice', 'data2', 'read')
                
                # Verify permissions are available in current session
                self.assertTrue(e.enforce('alice', 'data1', 'read'))
                self.assertTrue(e.enforce('alice', 'data2', 'read'))
                
                # Rollback the transaction
                await external_session.rollback()
            
            # Verify permissions do not persist after rollback with new session
            async with async_session_factory() as new_session:
                new_adapter = Adapter(engine, db_session=new_session)
                new_enforcer = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), new_adapter)
                await new_enforcer.load_policy()
                
                self.assertFalse(new_enforcer.enforce('alice', 'data1', 'read'))
                self.assertFalse(new_enforcer.enforce('alice', 'data2', 'read'))
        
        finally:
            # Clean up
            if os.path.exists(db_file.name):
                os.unlink(db_file.name)

    async def test_external_session_with_save_policy(self):
        """Test save_policy with external session."""
        # Create a temporary database file
        db_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        db_file.close()
        
        try:
            # Create async engine
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_file.name}", future=True)
            
            # Create session factory
            async_session_factory = async_sessionmaker(engine, expire_on_commit=False)
            
            # Test with external session
            async with async_session_factory() as external_session:
                # Create adapter with external session
                adapter = Adapter(engine, db_session=external_session)
                
                # Create table
                await adapter.create_table()
                
                # Create enforcer
                e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
                await e.load_policy()
                
                # Add permissions
                await e.add_permission_for_user('alice', 'data1', 'read')
                await e.add_permission_for_user('bob', 'data2', 'write')
                
                # Save policy (should use external session)
                await e.save_policy()
                
                # Commit the transaction
                await external_session.commit()
            
            # Verify policies persist after commit with new session
            async with async_session_factory() as new_session:
                new_adapter = Adapter(engine, db_session=new_session)
                new_enforcer = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), new_adapter)
                await new_enforcer.load_policy()
                
                self.assertTrue(new_enforcer.enforce('alice', 'data1', 'read'))
                self.assertTrue(new_enforcer.enforce('bob', 'data2', 'write'))
        
        finally:
            # Clean up
            if os.path.exists(db_file.name):
                os.unlink(db_file.name)

    async def test_backward_compatibility(self):
        """Test that existing behavior is preserved."""
        # Create a temporary database file
        db_file = tempfile.NamedTemporaryFile(suffix='.db', delete=False)
        db_file.close()
        
        try:
            # Create async engine
            engine = create_async_engine(f"sqlite+aiosqlite:///{db_file.name}", future=True)
            
            # Create adapter without external session (original way)
            adapter = Adapter(engine)
            
            # Create table
            await adapter.create_table()
            
            # Create enforcer
            e = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), adapter)
            await e.load_policy()
            
            # Add permissions (should auto-commit)
            await e.add_permission_for_user('alice', 'data1', 'read')
            await e.add_permission_for_user('alice', 'data2', 'read')
            
            # Verify permissions are committed automatically
            self.assertTrue(e.enforce('alice', 'data1', 'read'))
            self.assertTrue(e.enforce('alice', 'data2', 'read'))
            
            # Create new adapter to verify persistence
            new_adapter = Adapter(engine)
            new_enforcer = casbin.AsyncEnforcer(get_fixture("rbac_model.conf"), new_adapter)
            await new_enforcer.load_policy()
            
            self.assertTrue(new_enforcer.enforce('alice', 'data1', 'read'))
            self.assertTrue(new_enforcer.enforce('alice', 'data2', 'read'))
        
        finally:
            # Clean up
            if os.path.exists(db_file.name):
                os.unlink(db_file.name)


if __name__ == "__main__":
    unittest.main()
