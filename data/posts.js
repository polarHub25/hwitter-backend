import * as userRepository from './auth.js';
import { db } from '../db/database.js';

const SELECT_JOIN = 'SELECT po.id, po.text, po.createDate , po.userId , us.username, us.name, us.url FROM posts as po JOIN users as us ON po.userId = us.id';
const ORDER_DESC = 'ORDER BY po.createDate DESC';
export async function getAll(){
    // return Promise.all(
    //     postsArr.map(async (post)=>{
    //         const { username, name, url } = await userRepository.findById(
    //             post.userId
    //         );
    //         return {...post, username, name, url};
    //     })        
    // );
    return db
    .execute(`${SELECT_JOIN} ${ORDER_DESC}`)
    .then(result => result[0]);
}

export async function getAllByUsername(username){
    // return getAll().then((postsArr) => 
    // postsArr.filter((post) => post.username === username));
    return db
    .execute(`${SELECT_JOIN} WHERE us.username=? ${ORDER_DESC}`, [username])
    .then(result => result[0]);
}

export async function getById(id){
    // const found = postsArr.find((post) => post.id === id);
    // if(!found){
    //     return null;
    // }
    // const { username, name, url } = await userRepository.findById(found.userId);
    // return { ...found, username, name, url};
    return db
    .execute(`${SELECT_JOIN} WHERE po.id=?`, [id])
    .then(result => result[0][0]);

}

export async function create(text, userId){
    // const post = {
    //     id: Date.now().toString(),
    //     text,
    //     createDate: new Date(),
    //     userId,
    // };
    // postsArr = [post, ...postsArr]; //배열 앞부분에 넣어야해서 push가 아닌 이런식으로 넣어주기
    // return getById(post.id);
    return db.execute(
        'INSERT INTO posts(text, createDate, userId) VALUES(?,?,?)',
        [text, new Date(), userId]
        ).then((result) => getById(result[0].insertId));
}

export async function update(id, text){
    // const post = postsArr.find(post => post.id === id);
    // if(post){
    // post.text = text;
    // }
    // return getById(post.id);
    return db.execute('UPDATE posts SET text=? WHERE id=?',[text,id])
    .then(() => getById(id));
}

export async function remove(id){
    //postsArr = postsArr.filter(post => post.id !== id);
    return db.execute('DELETE FROM posts WHERE id=?' , [id]);
}