
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

export async function getAll(){
    return postsArr;
}

export async function getAllByUsername(username){
    return postsArr.filter((post) => post.username ===username);
}

export async function getById(id){
    return postsArr.find((post) => post.id === id);
}

export async function create(text, name, username){
    const post = {
        id: Date.now().toString(),
        text,
        createDate: new Date(),
        name,
        username,
    };
    postsArr = [post, ...postsArr]; //배열 앞부분에 넣어야해서 push가 아닌 이런식으로 넣어주기
    return post;
}

export async function update(id, text){
    const post = postsArr.find(post => post.id === id);
    if(post){
    post.text = text;
    }
    return post;
}

export async function remove(id){
    postsArr = postsArr.filter(post => post.id !== id);
}