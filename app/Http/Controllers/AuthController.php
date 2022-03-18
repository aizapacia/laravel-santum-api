<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Http\Response;
use Illuminate\Support\Facades\Hash;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $field =$request -> validate([
            'name' => ['required','string'],
            'email' => ['required','string','unique:users','email'],
            'password' => ['required','string','confirmed']
        ]);

        $user = user::create([
            'name'=> $field['name'],
            'email'=>$field['email'],
            'password' => bcrypt($field['password'])
        ]);

        $token = $user-> createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token'=> $token
        ];

        return response ($response, 201);
    }

    public function logout(Request $request)
    {
        auth()->user()->tokens()->delete();

        return[
            'message' => 'Logged out'
        ];
    }


    public function login(Request $request)
    {
        $field =$request -> validate([
            'email' => ['required','string'],
            'password' => ['required','string']
        ]);

        //CHECK EMAIL
        $user = User::where('email', $field['email']) -> first();

        if(!$user || !Hash::check($field['password'], $user->password ))
        {
            return response([
                'message' => 'Bad creds'
            ], 401);
        }

        $token = $user-> createToken('myapptoken')->plainTextToken;

        $response = [
            'user' => $user,
            'token'=> $token
        ];

        return response ($response, 201);
    }


}
