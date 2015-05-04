<?php namespace AdamWathan\PasswordUpdater;

use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\Guard;
use Symfony\Component\HttpFoundation\Request;

class UpdatingGuard implements Guard
{
    protected $guard;
    protected $update_password;
    protected $request;
    protected $check_functions = [];

    public function __construct(Guard $guard, Closure $update_password, Request $request = null)
    {
        $this->guard = $guard;
        $this->update_password = $update_password;
        $this->request = $request;
    }

    public function addCheck($check_function)
    {
        $this->check_functions[] = $check_function;
    }

    public function once(array $credentials = [])
    {
        $this->updatePasswordIfNeeded($credentials);
        return $this->guard->once($credentials);
    }

    public function attempt(array $credentials = [], $remember = false, $login = true)
    {
        $this->updatePasswordIfNeeded($credentials);
        return $this->guard->attempt($credentials, $remember, $login);
    }

    public function basic($field = 'email')
    {
        $this->updatePasswordIfNeeded($this->getBasicCredentials($field));
        return $this->guard->basic($field);
    }

    public function onceBasic($field = 'email')
    {
        $this->updatePasswordIfNeeded($this->getBasicCredentials($field));
        return $this->guard->onceBasic($field);
    }

    protected function getBasicCredentials($field)
    {
        return [
            $field => $this->getRequest()->getUser(),
            'password' => $this->getRequest()->getPassword(),
        ];
    }

    protected function getRequest()
    {
        return $this->request ?: Request::createFromGlobals();
    }

    public function validate(array $credentials = [])
    {
        $this->updatePasswordIfNeeded($credentials);
        return $this->guard->validate($credentials);
    }

    protected function updatePasswordIfNeeded($credentials)
    {
        foreach ($this->check_functions as $check_function) {
            if ($check_function($credentials)) {
                $this->update_password->__invoke($credentials);
                break;
            }
        }
    }

    // Just delegate everything else
    public function check()
    {
        return $this->guard->check();
    }

    public function guest()
    {
        return $this->guard->guest();
    }

    public function user()
    {
        return $this->guard->user();
    }

    public function login(Authenticatable $user, $remember = false)
    {
        return $this->guard->login($user, $remember);
    }

    public function loginUsingId($id, $remember = false)
    {
        return $this->guard->loginUsingId($id, $remember);
    }

    public function viaRemember()
    {
        return $this->guard->viaRemember();
    }

    public function logout()
    {
        return $this->guard->logout();
    }
}
