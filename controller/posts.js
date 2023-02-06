import { getSocketIO } from '../connection/socket.js';
import * as postRepository from '../data/posts.js';

export async function getPosts(req,res){
    const username = req.query.username;
    console.log('controller get ' , username);
    const data = await(username 
        ? postRepository.getAllByUsername(username)
        : postRepository.getAll());
    res.status(200).json(data);
}

export async function getPost( req, res){
    const id = req.params.id;
    const post = await postRepository.getById(id);
    if(post){
        res.status(200).json(post);
    }else{
        res.status(404).json({message: `Post id(${id}) not found`});
    }
}

export async function createPost(req,res){
    const {text} = req.body;
    const post = await postRepository.create(text, req.userId);
    res.status(201).json(post);
    getSocketIO().emit('posts', post);
}

export async function updatePost (req,res,next){
    const id = req.params.id;
    const text = req.body.text;
    const post = await postRepository.getById(id);
    
    if(!post){
        return res.sendStatus(404);
    }
    if(post.userId !== req.userId){
        return res.sendStatus(403);
    }
    const updated = await postRepository.update(id, text);
    res.status(200).json(updated);
}

export async function deletePost(req,res,next){
    const id = req.params.id;
    const post = await postRepository.getById(id);
    if(!post){
        return res.sendStatus(404);
    }
    if(post.userId !== req.userId){
        return res.sendStatus(403);
    }

    await postRepository.remove(id);
    res.sendStatus(204);
}