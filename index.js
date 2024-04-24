// import express
const express = require('express');

// create new express app and assign it to `app` constant
const application = express();

// server starts listening the `PORT`
application.listen(3000, () => {
    console.log(`Server running at: http://localhost:3000/`);
});