import * as postRepository from '../data/posts.js';

export async function getPosts(req,res){
    const username = req.query.username;
    const data = await(username 
        ? postRepository.getAllByUsername(username)
        : postRepository.getAll());
    console.log('posts select');
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
    const {text, name, username} = req.body;
    const post = await postRepository.create(text, name, username);
    res.status(201).json(post);
}

export async function updatePost (req,res,next){
    const id = req.params.id;
    const text = req.body.text;
    const post = await postRepository.update(id, text);
    if(post){
        res.status(200).json(post);
    }else{
        res.status(404).json({message: `Post id(${id}) not found`});
    }
}

export async function deletePost(req,res,next){
    const id = req.params.id;
    await postRepository.remove(id);
    res.sendStatus(204);
}