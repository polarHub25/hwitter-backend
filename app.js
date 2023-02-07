import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import helmet from 'helmet';
import 'express-async-errors';
import postsRouter from './router/posts.js';
import authRouter from './router/auth.js';
import {config} from './config.js';
import {initSocket} from './connection/socket.js';
import { sequelize} from './db/database.js';

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
app.use('/auth', authRouter);

app.use((req,res,next) => {
    res.sendStatus(404)
});

app.use((error, req,res,next)=>{
    console.error(error);
    //res.status(500).send('Sorry, try later!');
    res.sendStatus(500);
});

//db.getConnection().then(connection => console.log(connection));

//Sequelize 연결 후 서버 실행
sequelize.sync().then(client => {
    //console.log(client);
    const server = app.listen(config.host.port);
    initSocket(server);
})

