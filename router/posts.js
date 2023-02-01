import express, { json } from 'express';
import 'express-async-errors';


let postsArr = [
    {
        id: '1',
        text: 'crud 테스트 중입니다~! ',
        createDate: Date.now().toString(),
        name: 'Bob',
        username: 'bob',
        url: 'https://widgetwhats.com/app/uploads/2019/11/free-profile-photo-whatsapp-1.png',
      },
      {
        id: '2',
        text: '트위터 클론 코딩!  ',
        createDate: Date.now().toString(),
        name: 'Ellie',
        username: 'ellie',
        url: 'https://widgetwhats.com/app/uploads/2019/11/free-profile-photo-whatsapp-1.png',
      },
      {
        id: '3',
        text: '테스트 코딩!  ',
        createDate: Date.now().toString(),
        name: 'Ellie',
        username: 'ellie',
        url: 'https://widgetwhats.com/app/uploads/2019/11/free-profile-photo-whatsapp-1.png',
      },
];

const router = express.Router();

// GET /posts
// GET /posts?username=:username
router.get('/',(req,res,next)=>{
    const username = req.query.username;

    const data = username ? postsArr.filter(post => post.username === username)
    : postsArr;
    console.log('posts select');
    res.status(200).json(data);
});


// GET /posts/:id
router.get('/:id', ( req, res, next) => {
    const id = req.params.id;
    const post = postsArr.find((post) => post.id === id);
   // console.log(id);
   // console.log(postsArr.find(t=>t.id));
    if(post){
        res.status(200).json(post);
    }else{
        res.status(404).json({message: `Post id(${id}) not found`});
    }
});

// POST /posts
router.post('/' , (req,res,next) => {
    const {text, name, username} = req.body;
    const post = {
        id: Date.now().toString(),
        text,
        createDate: new Date(),
        name,
        username,
    };
    postsArr = [post, ...postsArr]; //배열 앞부분에 넣어야해서 push가 아닌 이런식으로 넣어주기
    res.status(201).json(post);

});

// PUT /posts/:id
router.put('/:id' , (req,res,next) => {
    const id = req.params.id;
    const text = req.body.text;
    const post = postsArr.find(post => post.id === id);
    if(post){
        post.text = text;
        res.status(200).json(post);
    }else{
        res.status(404).json({message: `Post id(${id}) not found`});
    }
});
// DELETE /posts/:id
router.delete('/:id' , (req,res,next) => {
    const id = req.params.id;
    postsArr = postsArr.filter(post => post.id !== id);
    res.sendStatus(204);
});

export default router;
