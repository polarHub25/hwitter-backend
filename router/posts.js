import express, { json } from 'express';
import 'express-async-errors';
import * as postController from '../controller/posts.js';
const router = express.Router();

// GET /posts
// GET /posts?username=:username
router.get('/', postController.getPosts); //함수를 리턴받지않고 호출만 하면 되므로 () 안붙임

// GET /posts/:id
router.get('/:id', postController.getPost);

// POST /posts
router.post('/' , postController.createPost);

// PUT /posts/:id
router.put('/:id' ,postController.updatePost);

// DELETE /posts/:id
router.delete('/:id' , postController.deletePost);

export default router;
