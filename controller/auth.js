import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import {} from 'express-async-errors';
import * as userRepository from '../data/auth.js';
import {config} from '../config.js';



export async function signup(req,res){
    const {username, password , name, email, url} = req.body;
    const found = await userRepository.findByUsername(username);
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
    const token = createJwtToken(userId); //cookie header : 다른 브라우저를 사용하는 사람들은 이용못함! 그러므로 바디에는 그대로 둠.
    setToken(res,token);
    res.status(201).json({token, username});
}

export async function login(req, res){
    const {username, password } = req.body;
    const user = await userRepository.findByUsername(username);
    if(!user){
        return res.status(401).json({message : 'Invalid user or password'});
    }const isValidPassword = await bcrypt.compare(password, user.password);
    if(!isValidPassword){
        return res.status(401).json({message : 'Invalid user or password'});
    }
    const token = createJwtToken(user.id);
    setToken(res,token);
    res.status(200).json({token, username});
}

export async function logout(req, res, next){
    res.cookie('token', '');
    res.status(200).json({message: 'User has benn logged out'});
}

function createJwtToken(id){
    return jwt.sign({id}, config.jwt.secretKey, {expiresIn: config.jwt.expiresInSec});
}

function setToken(res,token){
    const options = {
        maxAge: config.jwt.expiresInSec * 1000 ,
        httpOnly: true,
        sameSite: 'none', //서버와 클라이언트가 동일한 도메인이 아니더라도 설정되게끔! 이 경우에는 secure: true 을 꼭 지정해주고 만료시간 지정하기
        secure: true, //
    }
    res.cookie('token' , token, options) //HTTP Only cookie 
}

export async function me(req,res,next) {
    const user = await userRepository.findById(req.userId);
    if(!user){
        return res.status(404).json({message: 'User not Found'});
    }
    res.status(200).json({token: req.token, username: user.user});
}