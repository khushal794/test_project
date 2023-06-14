const express = require('express')
const bcrypt = require("bcrypt");
const app = express();
const cors = require('cors')
const port = 8081;
const connection=require("./Database/connection.js");
const jwt=require("jsonwebtoken");
// const register =require("./controllers/auth.js");
// const login=require("./controllers/auth.js");
const dotenv=require("dotenv");

app.listen(port,()=>{
    console.log(`Server is running on http://localhost:${port}`)
})
// const connection = mysql.createConnection({
//     host:"127.0.0.1",
//     user:"root",
//     password:"root",
//     database:"lib_mgmt"
// })

dotenv.config();

connection.connect((err)=>{
    if(err){
        console.error("Error ",err)
        return
    }
    return console.log("Connected to MySQL!!")
})
app.use(express.json())
app.use(cors())
app.post("/auth/register",async (req, res) => {
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
            if (error) {
                console.log(error);
                return res.json("Error inserting user!!");}
            
            const userId = result.insertId;
            connection.query(
              "INSERT INTO session_storage(id, status) VALUES (?, ?)",
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
  });
  //login Api
  
  app.post("/auth/login",async (req,res)=>{
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
             res.status(400).json({message:console.log(err)})
      }
  });
//USER APIS.......................
//signup api
// app.post("/auth/register",register);
// app.post("/auth/login",login);

// app.post('/signup', (req, res) => {
//     const { fname, lname, email, password, mobile } = req.body;
//     console.log("req.body")
//     console.log(req.body)
//     console.log('ENDS')
//     connection.query("SELECT * FROM user WHERE email=?", [email], (err, results) => {
//         if (err) throw err;
//         if (results.length > 0) {
//             return res.status(400).json({ error: 'Email already exists' });
//         }
//         bcrypt.hash(password, 10, (err, hashedPassword) => {
//             if (err) throw err;
//             connection.query("INSERT INTO user(fname, lname, email, password, mobile) VALUES (?, ?, ?, ?, ?)", [
//                 fname,
//                 lname,
//                 email,
//                 hashedPassword,
//                 mobile
//             ], (error, result) => {
//                 if (error) return res.json("Error inserting user!!");
//                 const userId = result.insertId;
//                 connection.query("INSERT INTO session_storage(uid, status) VALUES (?, ?)", [userId, true], (err, results) => {
//                     if (err) throw err;
//                     return res.status(200).json({ res: 'User successfully signed up' });
//                 });
//             });
//         });
//     });
// });
//...................................................................//
//login api
// app.post('/login', (req, res) => {
//     const { email, password } = req.body;
//     connection.query("SELECT * FROM user WHERE email = ?", [email], (err2, res2) => {
//         if (err2) throw err2;
//         if (res2.length === 0) {
//             return res.status(401).json({ error: 'SignUp First!!' });
//         }
//         else{
//             if(password===res2[0].password){
//                 return res.status(200).json({ message: 'Login successful' })
//             }
//             else{
//                 return res.status(401).json({ error: 'Invalid password' });
//             }
//         }

        // const storedPassword = res2[0].password;
        // bcrypt.compare(password, storedPassword, (err3, res3) => {
        //     if (err3) throw err3;
        //     if (res3) {
        //         connection.query("SELECT uid from user where email=?", [email], (err4, res4) => {
        //             if (err4) throw err4;
        //             const userId = res4[0].uid
        //             connection.query("UPDATE session_storage SET status=? WHERE uid=?", [true,userId], (err5, res5) => {
        //                 if (err5) throw err5;
        //                 return res.status(200).json({ message: 'Login successful' });
        //             });
        //         });                
        //     } else {
        //         return res.status(401).json({ error: 'Invalid email or password' });
        //     }
        // });
    // });
// });
//...................................................................//
//get admin status
app.get('/getAdStatus',(req,res)=>{
    const {email}= req.body;
    connection.query("Select isadmin from user WHERE email=?",[
        email
    ],(error,result)=>{
        if(error) {
            return res.json("Error, ",error)
        }
        return res.status(200).json(result)
    })
});
//...................................................................//
//logout api
app.post('/logout', (req, res) => {
    const { email } = req.body;
        connection.query("SELECT uid from user where email=?", [email], (err2, res2) => {
            if (err2) throw err2;
            if (res2.length===0){
                return res.status(401).json({ error: 'Email does not exist!!' });
            }
            else{
                const userId = res2[0].uid
            connection.query("select * from  session_storage where status=? AND  uid=?", [true,userId], (err3, res3) => {
                if (err3) throw err3;
                if (res3.length===0){
                    return res.status(401).json({ error: 'User already logged Out' });
                }
                else{
                    connection.query("UPDATE session_storage SET status=? WHERE uid=?", [false,userId], (err4, res4) => {
                        if (err4) throw err4;
                        return res.status(200).json({ message: 'Logout successful' });
                    });
                }
            });
        }
        });  
    });

//..................................................................//
//update user password w.r.t email

app.patch('/resetpassword', (req, res) => {
    console.log('Here it is ')
    const { password, email } = req.body;
    console.log(email)
    console.log(password)
    bcrypt.hash(password, 10, (err, hashedPassword) => {
        if (err) throw err;
        connection.query("UPDATE user SET password = ? WHERE email = ?", [
            hashedPassword,
            email
        ], (error, result) => {
            if (error) {
                throw error; // Throw the `error` variable instead of `err`
            }
            return res.status(200).json({ message: "Successfully Updated User!" });
        });
    });
  });
//..................................................................//
///APIS for Books
app.get("/books", (req, res) => {
    const q = "Select * from books";
    connection.query(q, (error, result) => {
        if (error) return res.json("Error retriving books!!");
        return res.json(result);
    });
});
//...................................................................//
// delete books by id

app.delete("/books/:bid", (req, res) => {
    const bid = req.params.bid;
    const q = "Delete from books where bid=?";
    connection.query(q, [bid], (error, result) => {
        if (error) return res.json("Error deleting books!!");
        return res.json("Deleting!!");
    });
});
//...................................................................//
//get books by id

app.get("/books/:bid", (req, res) => {
    const bid = req.params.bid;
    const q = "Select * from books where bid=?";
    connection.query(q, [bid], (error, result) => {
        if (error) return res.json("Error retriving book!!");
        return res.json(result);
    });

});
//...................................................................//
//search book by title

app.get("/books/search", (req, res) => {
    console.log('hello from another side');
    const searchTerm = req.query.searchTerm;
    console.log(searchTerm);
    const q = "SELECT * FROM books WHERE title LIKE ?";
    const searchTermWithWildcards = `%${searchTerm}%`;
    connection.query(q, searchTermWithWildcards, (error, results) => {
      if (error) {
        console.error("Error executing query:", error);
        return res.status(500).json({ error: "An error occurred" });
      }
      res.json(results);
    });
  });
//...................................................................//
//patch books by id

app.patch("/books/:bid", (req, res) => {
    const bookId = req.params.bid;
    const q =
        "Update books set `title`=? ,`image`=? ,`description`=?, `price`=?, `author`=?,`offers`=? where bid = ?";
    const values = [
        req.body.title,
        req.body.image,
        req.body.description,
        req.body.price,
        req.body.author,
        req.body.offers,
    ];
    connection.query(q, [...values, bookId], (error, result) => {
        if (error) return res.json("Error updating books!!");
        return res.json("Book Updated Successfully!!");
    });
});
//...................................................................//
//insert books

app.post("/books", (req, res) => {
    const q =
        "INSERT into books(`title` ,`image`,`description`, `price`, `author`,`offers`) values(?)";
    const values = [
        req.body.title,
        req.body.image,
        req.body.description,
        req.body.price,
        req.body.author,
        req.body.offers,
    ];
    connection.query(q, [values], (error, result) => {
        if (error) return res.json("Error inserting books!!");
        return res.json(result);
    });
});
//...................................................................//

