<?php

use AdamWathan\PasswordUpdater\UpdatingGuard;

class UpdatingGuardTest extends PHPUnit_Framework_TestCase
{
    public function test_it_updates_password_on_once_if_it_passes_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();

        $credentials = ['email' => 'adam@example.com', 'password' => 'secret'];

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        });
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->once($credentials);

        $update_password->shouldHaveReceived('update')->with($credentials);
        $guard->shouldHaveReceived('once')->with($credentials);
    }

    public function test_it_doesnt_update_passwords_on_once_if_it_doesnt_pass_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();

        $credentials = ['email' => 'adam@example.com', 'password' => 'wrong'];

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        });
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->once($credentials);

        $update_password->shouldNotHaveReceived('update');
        $guard->shouldHaveReceived('once')->with($credentials);
    }

    public function test_it_checks_against_multiple_user_checks()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();

        $credentials = ['email' => 'adam@example.com', 'password' => 'secret'];

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        });
        $updatingGuard->addCheck(function ($credentials) {
            return false;
        });
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->once($credentials);

        $update_password->shouldHaveReceived('update')->with($credentials);
        $guard->shouldHaveReceived('once')->with($credentials);
    }

    public function test_it_updates_password_on_attempt_if_it_passes_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();

        $credentials = ['email' => 'adam@example.com', 'password' => 'secret'];

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        });
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->attempt($credentials, $remember = false, $login = false);

        $update_password->shouldHaveReceived('update')->with($credentials);
        $guard->shouldHaveReceived('attempt')->with($credentials, $remember, $login);
    }

    public function test_it_doesnt_update_passwords_on_attempt_if_it_doesnt_pass_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();

        $credentials = ['email' => 'adam@example.com', 'password' => 'wrong'];

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        });
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->attempt($credentials, $remember = false, $login = false);

        $update_password->shouldNotHaveReceived('update');
        $guard->shouldHaveReceived('attempt')->with($credentials, $remember, $login);
    }

    public function test_it_updates_password_on_basic_if_it_passes_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();
        $request = Mockery::mock('Symfony\Component\HttpFoundation\Request');
        $request->shouldReceive([
            'getUser' => 'adam@example.com',
            'getPassword' => 'secret',
        ]);

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        }, $request);
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->basic('email');

        $update_password->shouldHaveReceived('update')->with(['email' => 'adam@example.com', 'password' => 'secret']);
        $guard->shouldHaveReceived('basic')->with('email');
    }

    public function test_it_doesnt_update_passwords_on_basic_if_it_doesnt_pass_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();
        $request = Mockery::mock('Symfony\Component\HttpFoundation\Request');
        $request->shouldReceive([
            'getUser' => 'adam@example.com',
            'getPassword' => 'wrong',
        ]);

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        }, $request);
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->basic('email');

        $update_password->shouldNotHaveReceived('update');
        $guard->shouldHaveReceived('basic')->with('email');
    }

    public function test_it_updates_password_on_oncebasic_if_it_passes_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();
        $request = Mockery::mock('Symfony\Component\HttpFoundation\Request');
        $request->shouldReceive([
            'getUser' => 'adam@example.com',
            'getPassword' => 'secret',
        ]);

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        }, $request);
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->onceBasic('email');

        $update_password->shouldHaveReceived('update')->with(['email' => 'adam@example.com', 'password' => 'secret']);
        $guard->shouldHaveReceived('onceBasic')->with('email');
    }

    public function test_it_doesnt_update_passwords_on_oncebasic_if_it_doesnt_pass_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();
        $request = Mockery::mock('Symfony\Component\HttpFoundation\Request');
        $request->shouldReceive([
            'getUser' => 'adam@example.com',
            'getPassword' => 'wrong',
        ]);

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        }, $request);
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->onceBasic('email');

        $update_password->shouldNotHaveReceived('update');
        $guard->shouldHaveReceived('onceBasic')->with('email');
    }

    public function test_it_updates_password_on_validate_if_it_passes_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();

        $credentials = ['email' => 'adam@example.com', 'password' => 'secret'];

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        });
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->validate($credentials);

        $update_password->shouldHaveReceived('update')->with($credentials);
        $guard->shouldHaveReceived('validate')->with($credentials);
    }

    public function test_it_doesnt_update_passwords_on_validate_if_it_doesnt_pass_a_check()
    {
        $guard = Mockery::spy('Illuminate\Contracts\Auth\Guard');
        $update_password = Mockery::spy();

        $credentials = ['email' => 'adam@example.com', 'password' => 'wrong'];

        $updatingGuard = new UpdatingGuard($guard, function ($credentials) use ($update_password) {
            $update_password->update($credentials);
        });
        $updatingGuard->addCheck(function ($credentials) {
            return $credentials['password'] === 'secret';
        });

        $updatingGuard->validate($credentials);

        $update_password->shouldNotHaveReceived('update');
        $guard->shouldHaveReceived('validate')->with($credentials);
    }
}
