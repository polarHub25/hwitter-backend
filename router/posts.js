import express, { json } from 'express';
import 'express-async-errors';
import {body} from 'express-validator';
import {validate} from '../middleware/validator.js';
import { isAuth } from '../middleware/auth.js';
import * as postController from '../controller/posts.js';

//validation
//sanitization
//contract Testing : Client-Server
//Proto-base

const router = express.Router();

const validatePost = [
    body('text')
        .trim()
        .isLength({min: 3})
        .withMessage('text should be at least 3 characters!'),
    validate,
];

// GET /posts
// GET /posts?username=:username
router.get('/', isAuth, postController.getPosts); //함수를 리턴받지않고 호출만 하면 되므로 () 안붙임

// GET /posts/:id
router.get('/:id', isAuth, postController.getPost);

// POST /posts
router.post('/' , isAuth, validatePost, postController.createPost);

// PUT /posts/:id
router.put('/:id' , isAuth, validatePost, postController.updatePost);

// DELETE /posts/:id
router.delete('/:id' , isAuth,  postController.deletePost);

export default router;
