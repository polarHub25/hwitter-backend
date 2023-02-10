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

const corsOption = {
    origin: config.cors.allowedOrigin,
    optionSuccessStatus: 200,
};

app.use(express.json());
app.use(morgan('tiny'));
app.use(helmet());
app.use(cors(corsOption));

app.use('/posts', postsRouter);
app.use('/auth', authRouter);

app.use((req,res,next) => {
    res.sendStatus(404)
});

app.use((error, req,res,next)=>{
    console.error(error);
    res.sendStatus(500);
});

//db.getConnection().then(connection => console.log(connection));

//Sequelize 연결 후 서버 실행
sequelize.sync().then(() => {
    console.log(`Server is Started....... ${new Date()}`);
    const server = app.listen(config.port);
    initSocket(server);
})

