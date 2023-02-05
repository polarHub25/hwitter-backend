import * as userRepository from './auth.js';

let postsArr = [
    {
        id: '1',
        text: 'crud 테스트 중입니다~! ',
        createDate: Date.now().toString(),
        userId: '1',
      },
      {
        id: '2',
        text: '트위터 클론 코딩!  ',
        createDate: Date.now().toString(),
        userId: '1',
      },
      {
        id: '3',
        text: '테스트 코딩!  ',
        createDate: Date.now().toString(),
        userId: '1',
      },
];

export async function getAll(){
    return Promise.all(
        postsArr.map(async (post)=>{
            const { username, name, url } = await userRepository.findById(
                post.userId
            );
            return {...post, username, name, url};
        })        
    );
}

export async function getAllByUsername(username){
    return getAll().then((postsArr) => 
    postsArr.filter((post) => post.username === username));
}

export async function getById(id){
    const found = postsArr.find((post) => post.id === id);
    if(!found){
        return null;
    }
    const { username, name, url } = await userRepository.findById(found.userId);
    return { ...found, username, name, url};
}

export async function create(text, userId){
    const post = {
        id: Date.now().toString(),
        text,
        createDate: new Date(),
        userId,
    };
    postsArr = [post, ...postsArr]; //배열 앞부분에 넣어야해서 push가 아닌 이런식으로 넣어주기
    return getById(post.id);
}

export async function update(id, text){
    const post = postsArr.find(post => post.id === id);
    if(post){
    post.text = text;
    }
    return getById(post.id);
}

export async function remove(id){
    postsArr = postsArr.filter(post => post.id !== id);
}