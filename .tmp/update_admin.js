db.getSiblingDB("seraph_ai_defense").users.updateOne({email:"buntbyron@gmail.com"}, {$set:{password:"$2b$12$fD6CSfCZoYSA9AhiOB8lku41JXL.Ysyf9GX9uux5SrfXh45hZWfPi"}});
printjson(db.getSiblingDB("seraph_ai_defense").users.findOne({email:"buntbyron@gmail.com"},{password:0}));
