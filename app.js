import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import 'express-async-errors';
import postsRouter from './router/posts.js';

const app = express();

// const corsOption = {
//     option: ['http://localhost:3000'],
//     optionSuccessStatus: 200,
//     Credential: true,

// };

app.use(express.json());
app.use(morgan('tiny'));
app.use(helmet());
app.use(cors());

app.use('/posts', postsRouter);

app.use((req,res,next) => {
    res.sendStatus(404)
});

app.use((error, req,res,next)=>{
    console.error(error);
    //res.status(500).send('Sorry, try later!');
    res.sendStatus(500);
});

app.listen(8080);