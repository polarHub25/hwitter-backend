import * as userRepository from './auth.js';
import {sequelize} from '../db/database.js';
import SQ, { Sequelize } from 'sequelize';
import {User} from './auth.js';

const DataTypes = SQ.DataTypes;

const Post = sequelize.define('post',{
    id:{
        type: DataTypes.INTEGER,
        autoIncrement: true,
        allowNull: false,
        primaryKey: true
      },
      text: {
        type: DataTypes.TEXT,
        allowNull: false,
      },
});
Post.belongsTo(User);

// const SELECT_JOIN = 'SELECT po.id, po.text, po.createDate , po.userId , us.username, us.name, us.url FROM posts as po JOIN users as us ON po.userId = us.id';
//const ORDER_DESC = 'ORDER BY po.createDate DESC';

const INCLUDE_USER ={
    attributes:[
        'id',
        'text',
        'createdAt', 
        'userId', 
        [Sequelize.col('user.name'), 'name'],
        [Sequelize.col('user.username'), 'username'],
        [Sequelize.col('user.url'), 'url'],
    ],
    include: {
        model: User,
        attributes: []
    },
};

const ORDER_DESC = {
    order: [['createdAt', 'DESC']],
};

export async function getAll(){
    return Post.findAll({...INCLUDE_USER, ...ORDER_DESC});
    // return Promise.all(
    //     postsArr.map(async (post)=>{
    //         const { username, name, url } = await userRepository.findById(
    //             post.userId
    //         );
    //         return {...post, username, name, url};
    //     })        
    // );
    // return db
    // .execute(`${SELECT_JOIN} ${ORDER_DESC}`)
    // .then(result => result[0]);
}

export async function getAllByUsername(username){
    return Post.findAll({...INCLUDE_USER, ...ORDER_DESC, include: {
        ...INCLUDE_USER.include, where: {username},
    }});
    // return getAll().then((postsArr) => 
    // postsArr.filter((post) => post.username === username));
    // return db
    // .execute(`${SELECT_JOIN} WHERE us.username=? ${ORDER_DESC}`, [username])
    // .then(result => result[0]);
}

export async function getById(id){
    return Post.findOne({
        where: {id},
        ...INCLUDE_USER
    });
    // const found = postsArr.find((post) => post.id === id);
    // if(!found){
    //     return null;
    // }
    // const { username, name, url } = await userRepository.findById(found.userId);
    // return { ...found, username, name, url};
    // return db
    // .execute(`${SELECT_JOIN} WHERE po.id=?`, [id])
    // .then(result => result[0][0]);

}

export async function create(text, userId){
    return Post.create({text, userId}) //
    .then((data) => this.getById(data.dataValues.id));
    // const post = {
    //     id: Date.now().toString(),
    //     text,
    //     createDate: new Date(),
    //     userId,
    // };
    // postsArr = [post, ...postsArr]; //배열 앞부분에 넣어야해서 push가 아닌 이런식으로 넣어주기
    // return getById(post.id);
    // return db.execute(
    //     'INSERT INTO posts(text, createDate, userId) VALUES(?,?,?)',
    //     [text, new Date(), userId]
    //     ).then((result) => getById(result[0].insertId));
}

export async function update(id, text){
    return Post.findByPk(id, INCLUDE_USER)
    .then(post => {
        post.text = text;
        return post.save();
    });
    // const post = postsArr.find(post => post.id === id);
    // if(post){
    // post.text = text;
    // }
    // return getById(post.id);
    // return db.execute('UPDATE posts SET text=? WHERE id=?',[text,id])
    // .then(() => getById(id));
}

export async function remove(id){
    return Post.findByPk(id)
    .then(post => {
        post.destroy();
    });
    //postsArr = postsArr.filter(post => post.id !== id);
    //return db.execute('DELETE FROM posts WHERE id=?' , [id]);
}