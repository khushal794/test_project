const bcrypt = require("bcrypt");
const connection = require("../Database/connection.js");

//Sign Up Api
const register = async (req, res) => {
  const { fname, lname, email, password, mobile } = req.body;
  const salt = await bcrypt.genSalt();
  const hashPassword = await bcrypt.hash(password, salt);
  console.log("Khushal Sharma");
  connection.query(
    "SELECT * FROM user WHERE email=?",
    [email],
    (err, results) => {
      if (err) throw err;
      if (results.length > 0) {
        return res.status(400).json({ error: "Email already exists" });
      }

      connection.query(
        "INSERT INTO user(fname, lname, email, password, mobile) VALUES (?, ?, ?, ?, ?)",
        [fname, lname, email, hashPassword, mobile],
        (error, result) => {
          if (error) return res.json("Error inserting user!!");
          const userId = result.insertId;
          connection.query(
            "INSERT INTO session_storage(uid, status) VALUES (?, ?)",
            [userId, true],
            (err, results) => {
              if (err) throw err;
              return res
                .status(200)
                .json({ res: "User successfully signed up" });
            }
          );
        }
      );
    }
  );
};
//login Api

const login=async (req,res)=>{
    try{
       const {email,password}=req.body;
       const [rows]=await connection.promise().query('select * from user where email=? ',[email]);
       const user=rows[0];
       if(!user){
        return res.status(400).json({ msg: 'User Does Not Exist!' });
       }
       const isMatch=await bcrypt.compare(password,user.password);
       if(!isMatch){
        return res.status(400).json({ msg: 'Invalid Credential' });
       }
       const token=jwt.sign({ id: user.id }, process.env.JWT_SECRET);
       delete user.password;
       res.status(200).json({ token, user });

    }catch(err){

    }
}

// const login = async (req, res) => {
//   try{
//     const { email, password } = req.body;
//     connection.query(
//         "SELECT * FROM user WHERE email = ?",
//         [email],
//         (err2, res2) => {
//           if (err2) throw err2;
//           if (res2.length === 0) {
//             return res.status(401).json({ error: "SignUp First!!" });
//           } else {
//             const isMatch=bcrypt.compare(password,res2[0].password);
//             if (isMatch) {
//               return res.status(200).json({ message: "Login successful" });
//             } else {
//               return res.status(401).json({ error: "Invalid password" });
//             }
//           }
    
    
//         }
//       );
//   }catch(err){
//     res.status(500).json({error:err.message})
//   }
//   const { email, password } = req.body;
//   connection.query(
//     "SELECT * FROM user WHERE email = ?",
//     [email],
//     (err2, res2) => {
//       if (err2) throw err2;
//       if (res2.length === 0) {
//         return res.status(401).json({ error: "SignUp First!!" });
//       } else {
//         if (password === res2[0].password) {
//           return res.status(200).json({ message: "Login successful" });
//         } else {
//           return res.status(401).json({ error: "Invalid password" });
//         }
//       }


//     }
//   );
// };



module.exports=register;
module.exports=login;