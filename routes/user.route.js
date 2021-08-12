const express = require("express");
const userRouter = express.Router();

const { User, Setting, DealAction, Deal } = require("../model");

const crypto = require("crypto");
const { validateToken } = require("../middleware");

const path = require("path");
const multer = require("multer");
const fs = require("fs");

var jwt = require("jsonwebtoken");
var bcrypt = require("bcryptjs");
var mailer = require("../utils/mailer");

// File Upload
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    fs.mkdir("./uploads/", (err) => {
      cb(null, "./uploads/");
    });
  },
  filename: (req, file, cb) => {
    // console.log(file);
    cb(null, "user_" + Date.now() + path.extname(file.originalname));
  },
});
const fileFilter = (req, file, cb) => {
  if (file.mimetype == "image/jpeg" || file.mimetype == "image/png") {
    cb(null, true);
  } else {
    cb(new Error("Try to upload .jpeg or .png file."), false);
  }
};
const upload = multer({ storage: storage, fileFilter: fileFilter });

// Define User Add
userRouter.post("/add", upload.single("photo"), async function (req, res) {
  try {
    console.log("body:", req.body);
    console.log("files:", req.file);

    if (req.body.password) {
      var hashedPassword = bcrypt.hashSync(req.body.password, 8);
      req.body.password = hashedPassword;
    }

    if (req.file && req.file.fieldname == "photo" && req.file.filename) {
      req.body.photo = req.file.filename;
    }

    const newUser = new User(req.body);
    let user = await newUser.save();

    // Create a token
    const payload = { user: user.email };
    const token = jwt.sign(payload, process.env.JWT_SECRET);

    var user_res = {
      _id: user._id,
      first_name: user.first_name,
      last_name: user.last_name,
      email: user.email,
      username: user.username,
    };

    res
      .status(200)
      .json({
        success: true,
        msg: "User added successfully",
        user: user_res,
        token,
      });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Defined User Get All
userRouter.get("/", async function (req, res) {
  try {
    const users = await User.find({ role: 2, status:1 },{ username:1 });
    res
      .status(200)
      .json({ success: true, msg: "User get successfully", users: users });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
});

// Defined User Login
userRouter.post("/login", async function (req, res) {
  try {
    var fullUrl = req.protocol + "://" + req.get("host");
    const { email, password } = req.body;
    const user = await User.findOne({ email: { $regex: `${email}`, $options: "i" } });
    if (!user) {
      return res
        .status(200)
        .json({ success: false, msg: "This email is not registered!" });
    }
    if (user.role !== 2) {
      return res
        .status(200)
        .json({ success: false, msg: "This email is not registered!" });
    }
    if (user.status == 2) {
      return res
        .status(200)
        .json({ success: false, msg: "Account is deactivated!" });
    }

    var match = await bcrypt.compare(password, user.password);
    console.log("Match:", match);
    if (match) {
      // Create a token
      const payload = { user: user.email };
      const token = jwt.sign(payload, process.env.JWT_SECRET);

      var user_res = {
        _id: user._id,
        contact_no: user.contact_no,
        first_name: user.first_name,
        last_name: user.last_name,
        email: user.email,
        username: user.username,
        date: user.created_at,
        calender_event_title: user.calender_event_title,
        photo:
          user.photo && fs.existsSync(`./uploads/${user.photo}`)
            ? `${fullUrl}/uploads/${user.photo}`
            : "",
      };
      res
        .status(200)
        .json({
          success: true,
          msg: "User logged-in successfully",
          user: user_res,
          token,
        });
    } else {
      res.status(200).json({ success: false, msg: "Invalid Credentials!" });
    }
  } catch (error) {
    res.status(400).json({ success: false, msg: error.message });
  }
});

module.exports = userRouter;

// Define Front Send Reset Link
userRouter.post("/sendResetLink", async function (req, res) {
  try {
    console.log("body:", req.body);
    console.log("files:", req.file);
    var fullUrl = req.protocol + "://" + req.get("host");

    const { email } = req.body;

    // Check Email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(200).json({ success: false, msg: "Email not found!" });
    }

    // Generate Random Token
    crypto.randomBytes(20, function (err, buffer) {
      var token = buffer.toString("hex");
      User.findByIdAndUpdate(
        { _id: user._id },
        {
          reset_password_token: token,
          reset_password_expires: Date.now() + 86400000,
        },
        { upsert: true, new: true, multi: true }
      ).exec(function (err, new_user) {
        console.log("nress:", new_user);

        var mailOptions = {
          to: new_user.email,
          from: process.env.MAILER_EMAIL_ID,
          template: "forgot-password-email",
          subject: "Password help has arrived!",
          context: {
            url: `${process.env.USER_RESET_URL}/${token}`,
            name: new_user.username,
          },
        };
        mailer.sendMail(mailOptions);
      });
    });
    // Send Mail

    res.status(200).json({ success: true, msg: "Mail sent successfully." });
  } catch (error) {
    res.status(400).json({ success: false, msg: error.message });
  }
});

// Define User Verify Reset Link
userRouter.post("/resetPassword", async function (req, res) {
  try {
    console.log("body:", req.body);
    console.log("files:", req.file);
    var fullUrl = req.protocol + "://" + req.get("host");

    const {
      reset_password_token,
      new_password,
      confirm_new_password,
    } = req.body;

    // Check Link
    const user = await User.findOne({
      reset_password_token: reset_password_token,
      reset_password_expires: { $gt: Date.now() },
    });
    if (!user) {
      return res
        .status(200)
        .json({
          success: false,
          msg: "Password reset token is invalid or has expired.",
        });
    }

    // Check New Password and Confirm New Password
    if (new_password !== confirm_new_password) {
      return res
        .status(200)
        .json({
          success: false,
          msg: "Confirm password and new password must be same!",
        });
    }

    let newData = {
      password: bcrypt.hashSync(new_password, 8),
      reset_password_token: "",
      reset_password_expires: "",
    };

    User.findOneAndUpdate(
      { _id: user._id },
      { $set: newData },
      { multi: true, new: true },
      function (err, new_user) {
        if (err) throw err;

        // Send Mail
        var mailOptions = {
          to: new_user.email,
          from: process.env.MAILER_EMAIL_ID,
          template: "reset-password-email",
          subject: "Password Reset Confirmation",
          context: {
            name: new_user.username,
          },
        };
        mailer.sendMail(mailOptions);
        res
          .status(200)
          .json({ success: true, msg: "Password updated successfully." });
      }
    );
  } catch (error) {
    res.status(400).json({ success: false, msg: error.message });
  }
});

// Define Profile Update
userRouter.post(
  "/updateProfile",
  upload.single("photo"),
  async function (req, res) {
    try {
      console.log("body:", req.body);
      console.log("files:", req.file);
      var fullUrl = req.protocol + "://" + req.get("host");

      const { _id, username, email, contact_no, calender_event_title } = req.body;

      // Check contact_no Or Username
      const check_unique = await User.find({
        $and: [{ $or: [{ contact_no }, { username }] }, { _id: { $ne: _id } }],
      }).count();
      if (check_unique) {
        return res
          .status(200)
          .json({
            success: false,
            msg: "Username or contact_no must be unique.",
          });
      }

      const user = await User.findById(_id);
      console.log("Iser", user);
      if (user) {
        var newData = {
          username,
          email,
          contact_no,
          calender_event_title
        };

        if (req.file && req.file.fieldname == "photo" && req.file.filename) {
          // Remove Old Profile Pic
          let path = `./uploads/${user.photo}`;
          if (user.photo && fs.existsSync(path)) {
            fs.unlinkSync(path);
          }
          newData.photo = req.file.filename;
        }

        User.findOneAndUpdate(
          { _id: _id },
          { $set: newData },
          { multi: true, new: true },
          function (err, user) {
            if (err) throw err;
            const payload = { user: user.email };
            const token = jwt.sign(payload, process.env.JWT_SECRET);

            var response_arr = {
              _id: user._id,
              username: user.username,
              email: user.email,
              contact_no: user.contact_no,
              status: user.status,
              date: user.created_at,
              calender_event_title: user.calender_event_title,
              photo:
                user.photo && fs.existsSync(`./uploads/${user.photo}`)
                  ? `${fullUrl}/uploads/${user.photo}`
                  : "",
            };
            res
              .status(200)
              .json({
                success: true,
                msg: "Profile updated successfully",
                user: response_arr,
                token,
              });
          }
        );
      } else {
        res.status(400).json({ success: false, msg: "User not found!" });
      }
    } catch (error) {
      res.status(400).json({ success: false, msg: error.message });
    }
  }
);

// Define User Change Password
userRouter.post("/changePassword", async function (req, res) {
  try {
    console.log("body:", req.body);
    console.log("files:", req.file);
    var fullUrl = req.protocol + "://" + req.get("host");

    const {
      current_user,
      old_password,
      new_password,
      cnew_password,
    } = req.body;

    // Check old Password
    const user = await User.findOne({ _id: current_user });
    if (!user) {
      return res.status(200).json({ success: false, msg: "User not found!" });
    }
    var match = await bcrypt.compare(old_password, user.password);
    if (!match) {
      return res
        .status(200)
        .json({ success: false, msg: "Current password is wrong!" });
    } else if (new_password.trim() !== cnew_password.trim()) {
      return res
        .status(200)
        .json({
          success: false,
          msg: "Confirm password and new password must be same!",
        });
    }

    let newData = {
      password: bcrypt.hashSync(new_password, 8),
    };

    User.findOneAndUpdate(
      { _id: current_user },
      { $set: newData },
      { multi: true, new: true },
      function (err, user) {
        if (err) throw err;
        res
          .status(200)
          .json({ success: true, msg: "Password updated successfully." });
      }
    );
  } catch (error) {
    res.status(400).json({ success: false, msg: error.message });
  }
});

//User Notifications add or update
userRouter.post("/addsettings", async function (req, res) {
  try {
    console.log("body:", req.body);
    const data = req.body;
    const current_user = req.body.user;
    const user = await Setting.findOne({ user: current_user });
    if (!user) {
      const newLog = new Setting(req.body);
      let setting = await newLog.save();

      return res
        .status(200)
        .json({
          success: true,
          msg: "Notification setting added!",
          data: setting,
        });
    } else {
      Setting.findOneAndUpdate(
        { user: current_user },
        { $set: data },
        { multi: true, new: true },
        function (err, user) {
          if (err) throw err;
          res
            .status(200)
            .json({
              success: true,
              msg: "Notification setting updated successfully.",
              data: user,
            });
        }
      );
    }
  } catch (error) {
    res.status(400).json({ success: false, msg: error.message });
  }
});

//Get Settings
userRouter.get("/settings/:id", async function (req, res) {
  try {
    const user = await Setting.findOne({ user: req.params.id });
    console.log(user);
    res
      .status(200)
      .json({ success: true, msg: "Settings get successfully", data: user });
  } catch (error) {
    res.status(400).json({ success: false, msg: error.message });
  }
});

//Get Profile
userRouter.get("/profile/:id", async function (req, res) {
  try {
    console.log(`req.params.id:${req.params.id}`);
    var won_deal_ratio = 0;
    var lost_deal_ratio = 0;
    var won_deal_values = 0;
    var lost_deal_values = 0;
    const user = await User.findOne({ _id: req.params.id });
    console.log(`user:${user}`);
    // Get Won Deal Ratio
    if (user) {
      // const total_deal_action = await Deal.find({}).count();
      // const total_deal_won_action = await DealAction.find({
      //   user: req.params.id,
      //   action: "deal_won",
      // })
      //   .populate({ path: "deal" })
      //   .lean();
      // new_total_deal_won_action = total_deal_won_action.filter(
      //   (wd) => wd && wd.deal !== null
      // );
      // let won_count = new_total_deal_won_action.length;
      // won_deal_ratio =
      //   total_deal_action > 0
      //     ? (parseInt(won_count) * 100) / parseInt(total_deal_action)
      //     : 0;

      let deal_value_arr = {};
      let deal_types = [{action:"deal_won"}, {action:"deal_lost"}];
      for (const type of deal_types) {
        // Get Action Deals
        const getDeals = await DealAction.find({ user:user._id, action:type.action },{deal:1}).sort({ updated_at: -1 });
        let dealIds = getDeals.map(d => d.deal);
        let deal_filter = {_id : { $in : dealIds },"responsible.value":user._id.toString() };
        const deals = await Deal.find(deal_filter,{_id:1,value:1}).lean();
        const totalValues = deals.reduce((acc, d) => (d.value) ? acc + parseFloat(d.value) : 0 , 0);
        deal_value_arr[type.action] = totalValues;
      }

      won_deal_values  = deal_value_arr['deal_won'] ? deal_value_arr['deal_won'] : 0;
      lost_deal_values = deal_value_arr['deal_lost'] ? deal_value_arr['deal_lost'] : 0;
      total_won_lost_deal_values = won_deal_values + lost_deal_values;

      won_deal_ratio = total_won_lost_deal_values > 0 ? ((parseInt(won_deal_values) * 100) / parseInt(total_won_lost_deal_values)) : 0;
      lost_deal_ratio = total_won_lost_deal_values > 0 ? ((parseInt(lost_deal_values) * 100) / parseInt(total_won_lost_deal_values)) : 0;
    }
    res
      .status(200)
      .json({
        success: true,
        msg: "Profile get successfully",
        user: user,
        won_deal_ratio: won_deal_ratio.toFixed(2),
        lost_deal_ratio: lost_deal_ratio.toFixed(2),
        won_deal_values: won_deal_values.toFixed(2),
        lost_deal_values: lost_deal_values.toFixed(2),
      });
  } catch (error) {
    res.status(400).json({ success: false, msg: error.message });
  }
});
