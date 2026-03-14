db.getSiblingDB("seraph_ai_defense").users.updateOne({email:"buntbyron@gmail.com"}, {$set:{password:"$2b$12$ckOWzjxj92JCFoV.GI5XtOmzgOZvpTV3o3xjS9ctwZvuNAqbDy86G"}});
printjson(db.getSiblingDB("seraph_ai_defense").users.findOne({email:"buntbyron@gmail.com"},{password:0}));
