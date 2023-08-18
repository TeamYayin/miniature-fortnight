/* eslint-disable no-unused-vars */
const express = require("express");
const app = express();
const csrf = require("tiny-csrf");
const { Vendor } = require("./models");
const bodyParser = require("body-parser");
var cookieParser = require("cookie-parser");
const path = require("path");

//Vendor auth
const passport = require("passport");
const LocalStrategy = require("passport-local");
const session = require("express-session");
const flash = require("connect-flash");
const connectEnsureLogin = require("connect-ensure-login");
const bcrypt = require("bcrypt");

const saltRounds = 10;
app.use(bodyParser.json());

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(flash());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser("cookie-monster-secret"));
app.use(csrf("0123456789iamthesecret9876543210", ["POST", "PUT", "DELETE"]));
app.use(express.static(path.join(__dirname, "public")));

// Vendor auth
app.use(
  session({
    secret: "my-secret-key-176172672",
    cookie: { maxAge: 24 * 60 * 60000 },
  })
);

app.use(function (request, response, next) {
  response.locals.messages = request.flash();
  next();
});

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new LocalStrategy(
    {
      usernameField: "emailAddress",
      passwordField: "password",
    },
    (username, password, done) => {
      console.log("Authenticating Vendor: ", username);
      Vendor.findOne({ where: { email: username } })
        .then(async (vendor) => {
          const matchPassword = await bcrypt.compare(password, vendor.password);
          if (matchPassword) {
            return done(null, vendor);
          } else {
            return done(null, false, { message: "Invalid Password" });
          }
        })
        .catch((error) => {
          return done(null, false, {
            message: "Not a Valid Vendor, Please Signup",
          });
        });
    }
  )
);

passport.serializeUser((vendor, done) => {
  console.log("Serializing user: ", vendor);
  done(null, vendor.id);
});

passport.deserializeUser((id, done) => {
  Vendor.findByPk(id)
    .then((vendor) => {
      done(null, vendor);
    })
    .catch((error) => {
      done(error, null);
    });
});

app.get("/", async (request, response) => {
  response.render("index", {
    title: "Todo Application",
    csrfToken: request.csrfToken(),
  });
});

app.get("/vendor-signup", async function (request, response) {
  response.render("vendorSignup", {
    csrfToken: request.csrfToken(),
    title: "Sign-up",
  });
});

app.post("/vendors", async function (request, response) {
  try {
    console.log("Firstname: ", request.body.firstName);
    const hashedPassword = await bcrypt.hash(request.body.password, 10);
    const complSystemVendor = await Vendor.create({
      companyName: request.body.companyName,
      contactPerson: request.body.contactPerson,
      phoneNumber: request.body.phoneNumber,
      serviceType: request.body.serviceType,
      email: request.body.emailAddress,
      password: hashedPassword,
    });
    request.login(complSystemVendor, (error) => {
      if (error) {
        return console.log(error);
      }
      response.redirect("/todos");
    });
  } catch (error) {
    console.log(error);
    return response.status(422).json(error);
  }
});

app.get("/vendor-login", (request, response) => {
  response.render("vendorLogin", {
    csrfToken: request.csrfToken(),
    title: "Login",
  });
});

app.post(
  "/session",
  passport.authenticate("local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  (request, response) => {
    response.redirect("/todos");
  }
);

app.get("/signout", (request, response, next) => {
  request.logout((err) => {
    if (err) {
      return next(err);
    }
    response.redirect("/");
  });
});

//todo routes
app.get("/vendor-home", (request, response) => {
  response.render("vendorHome", {
    csrfToken: request.csrfToken(),
    title: "Login",
    headingTitle: "Vendor Home",
    vendorCompanyName: "Peter",
    vendorCompanyCode: "123456",
  });
});
//todo emp home page, vendor home page and hr role home page
app.get("/emp-home", (request, response) => {
  response.render("empHome", {
    csrfToken: request.csrfToken(),
    title: "Login",
    headingTitle: "Employee Home",
    userFirstName: "Peter",
  });
});
app.get("/hr-home", (request, response) => {
  response.render("hrHome", {
    csrfToken: request.csrfToken(),
    title: "Login",
    headingTitle: "HR Home",
    userFirstName: "Rajesh",
  });
});
module.exports = app;
