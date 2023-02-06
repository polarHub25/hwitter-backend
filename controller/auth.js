import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import {} from 'express-async-errors';
import * as userRepository from '../data/auth.js';
import {config} from '../config.js';



export async function signup(req,res){
    const {username, password , name, email, url} = req.body;
    const found = await userRepository.findByUsername(username);
    console.log('authController signup' , req.body.userId);
    if(found){
        return res.status(409).json({message: `{$username} already exists`})
    }
    const hashed = await bcrypt.hash(password, config.bcrypt.saltRounds);
    const userId = await userRepository.createUser({
        username, 
        password: hashed,
        name,
        email,
        url,
    });
    console.log('auth controller signup에서의 userId', userId);
    const token = createJwtToken(userId);
    res.status(201).json({token, username});
}

export async function login(req, res){
    const {username, password } = req.body;
    console.log('authController login' , req.body.username);
    console.log('authController login' , req.body.userId);
    const user = await userRepository.findByUsername(username);
    if(!user){
        return res.status(401).json({message : 'Invalid user or password'});
    }const isValidPassword = await bcrypt.compare(password, user.password);
    if(!isValidPassword){
        return res.status(401).json({message : 'Invalid user or password'});
    }
    const token = createJwtToken(user.id);
    res.status(200).json({token, username});
}

function createJwtToken(id){
    console.log('createJwtToken::', id);
    console.log('createJwtToken secret key ', config.jwt.secretKey);
    return jwt.sign({id}, config.jwt.secretKey, {expiresIn: config.jwt.expiresInSec});
}

export async function me(req,res,next) {
    console.log('AuthController::', req.userId)
    const user = await userRepository.findById(req.body.userId);
    if(!user){
        return res.status(404).json({message: 'User not Found'});
    }
    res.status(200).json({token: req.token, username: user.user});
}