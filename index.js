// console.log(process.argv);
const express = require("express");
const app = express();
const fs = require('fs');
const path = require("path");
const server = require("http").createServer(app);
// const url = require("url");
const port = 4859;
// console.log(process);
const ModbusRTU = require("modbus-serial");
const io = require('socket.io')(server);
// const compression = require('compression');
const mongojs = require('mongojs');
const crypto = require('crypto');
const config = JSON.parse(fs.readFileSync(path.join(__dirname, './conf/config.json'), 'utf-8'));
// const db = mongojs('mongodb://'+config.mongodb.user+':'+config.mongodb.password+'@localhost:27017/'+config.mongodb.database)
const db = mongojs('mongodb://board:safiboard@localhost:27017/history')
const client = new ModbusRTU();
const { setImmediate } = require("timers");
const passport = require('passport');
const Strategy = require('passport-local').Strategy;
const users = require('./users.js');
const secret = 'Einstein';
const algorithm = 'aes-192-cbc';
const key = crypto.scryptSync(secret, 'bridge', 24);
const iv = Buffer.alloc(16, 9);
const decipher = crypto.createDecipheriv(algorithm, key, iv);
let encrusers = fs.readFileSync(path.join(__dirname+'/conf', 'users.json'), 'utf-8');
let decrusers = decipher.update(encrusers, 'hex', 'utf8');
decrusers += decipher.final('utf8');
// app.use(express.json());
// console.log(crypto.createHash('md5').update('').digest("hex"));
passport.use(new Strategy(
  (username, password, cb) => {
    users.findByUsername(username, (err, user)=> {
      if (err) { return cb(err); }
      if (!user) { return cb(null, false); }
      if (user.password != crypto.createHash('md5').update(password).digest("hex")) { return cb(null, false); }
      return cb(null, user);
    });
  }));
  passport.serializeUser((user, cb)=> {
    cb(null, user.id);
  });
  
  passport.deserializeUser((id, cb)=> {
    users.findById(id,(err, user)=> {
      if (err) { return cb(err); }
      cb(null, user);
    });
  });

  app.use(require('body-parser').urlencoded({ extended: true }));
  app.use(require('express-session')({ secret: secret, resave: false, saveUninitialized: false }));
  
  // Initialize Passport and restore authentication state, if any, from the
  // session.
  app.use(passport.initialize());
  app.use(passport.session());

app.use('/public', express.static(path.join(__dirname, 'public')));

app.get('/login',
  (req, res)=>{
    res.sendFile("login.html", {root: __dirname});
  });
  
app.post('/login', 
  passport.authenticate('local', { failureRedirect: '/login' }),
  (req, res) => {
    res.redirect('/admin');
  });
  
app.get('/logout',
  (req, res)=>{
    req.logout();
    res.redirect('/');
  });

app.get("/admin",(req, res) => {
  // console.log(req.query);
     const isAuthenticated = !!req.user;
    //console.log(req);
    // if (isAuthenticated) {
    //   console.log(req.user,req.session.id);
    // } else {
    //   console.log(req.user);
    // }
    res.sendFile(isAuthenticated ? "admin.html" : "login.html", { root: __dirname });
});
app.get('/changepassword',
  (req, res)=>{
    res.sendFile("changepassword.html", {root: __dirname});
  });
  
app.post('/changepassword', 
  passport.authenticate('local', { failureRedirect: '/changepassword' }),
  (req, res) => {
    // console.log(req.body);
    if (req.body.newpassword == req.body.newpassword2){
      let userRecord = JSON.parse(decrusers);
      userRecord.map(user=>{
        // if (user.username == req.body.username){user.password = crypto.createHash('md5').update(req.body.newpassword).digest("hex")};
        if (user.username == req.body.username){user.password = crypto.createHash('md5').update(req.body.newpassword).digest("hex")};
        return user;
      });
      const cipher = crypto.createCipheriv(algorithm, key, iv);
      let encrecord = cipher.update(JSON.stringify(userRecord), 'utf8', 'hex');
      encrecord += cipher.final('hex');
      fs.writeFileSync(path.join(__dirname+'/conf', 'users.json'), encrecord);
      
      // res.end('Password Changed');
      // res.redirect('/login');
      res.sendFile("loginforchangepwdsuccess.html", {root: __dirname});
    }
    else{
      res.redirect('/changepassword')
    }
  });
app.get("/history", (req, res) => {
  res.sendFile("history.html", {root: __dirname});
});
app.get("/", (req, res) => {
  res.sendFile("observer.html", {root: __dirname});
});
app.get("/historydebug", (req, res) => {
  res.sendFile("historydebug.html", {root: __dirname});
});

io.on('connect', (socket) => {
  // var dashboardName = url.parse(socket.handshake.headers.referer, true).query.dashboard;
  var dashboardName = new URL(socket.handshake.headers.referer).searchParams.get('dashboard');
  
  // console.log(socket.handshake.headers.referer.split('=',2));
  if (dashboardName == null) {
    dashboardName = 'index';
  };
  // console.log(dashboardName);
  // console.log(`new connection ${socket.id}`);

  var devices = fs.readFileSync(path.join(__dirname+'/conf', 'devices.json'), 'utf-8');
  var gridlayout, widgets, dashboards;
  if (fs.existsSync(path.join(__dirname+'/conf', 'gridlayout' + dashboardName + '.json'))) {
    gridlayout = fs.readFileSync(path.join(__dirname+'/conf', 'gridlayout' + dashboardName + '.json'), 'utf-8');
  } else {
    gridlayout = fs.readFileSync(path.join(__dirname+'/conf', 'gridlayoutblank.json'), 'utf-8');
  };
  if (fs.existsSync(path.join(__dirname+'/conf', 'widgets' + dashboardName + '.json'))) {
    widgets = fs.readFileSync(path.join(__dirname+'/conf', 'widgets' + dashboardName + '.json'), 'utf-8');
  } else {
    widgets = fs.readFileSync(path.join(__dirname+'/conf', 'widgetsblank.json'), 'utf-8');
  };
  dashboards = fs.readFileSync(path.join(__dirname+'/conf', 'dashboards.json'), 'utf-8');
  // var historyGridLayout = fs.readFileSync(path.join(__dirname, 'historyLayout.json'), 'utf-8');
  // var historyWidgets = fs.readFileSync(path.join(__dirname, 'historyWidgets.json'), 'utf-8');
  // console.log(devices)
  io.emit("display", devices, gridlayout, widgets, dashboards);
  // io.emit("history-display", historyGridLayout,historuWidgets);
  //console.log(socket);

  //io.emit("update-device-tree",devices);
  socket.on('update-gridLayout-widgets', (newGridLayout, newWidgets) => {
    var newGridLayout = JSON.stringify(newGridLayout);
    var newWidgets = JSON.stringify(newWidgets);
    // console.log(newWidgets);
    fs.writeFile(path.join(__dirname+'/conf', 'gridlayout' + dashboardName + '.json'), newGridLayout, () => {
      // console.log(error);
    });
    fs.writeFile(path.join(__dirname+'/conf', 'widgets' + dashboardName + '.json'), newWidgets, () => {
      // console.log(error);
    });

  });
  socket.on('update-gridLayout', (newGridLayout) => {
    var newGridLayout = JSON.stringify(newGridLayout);
    // console.log(newWidgets);
    fs.writeFile(path.join(__dirname+'/conf', 'gridlayout' + dashboardName + '.json'), newGridLayout, () => {
      // console.log(error);
    });

  });
  socket.on('update-devices-builtInViews', (deviceList, allTextGrid, allGaugeGrid, allBarGrid, allLineGrid, oneTableGrid, indexOverViewGrid, allTextWidgets, allGaugeWidgets, allBarWidgets, allLineWidgets, oneTableWidgets,indexOverViewWidgets) => {
    // var deviceListJson = JSON.stringify(deviceList);
    // console.log(deviceListJson);
    fs.writeFileSync(path.join(__dirname+'/conf', 'devices.json'), JSON.stringify(deviceList));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'gridlayoutallText.json'), JSON.stringify(allTextGrid));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'gridlayoutallGauge.json'), JSON.stringify(allGaugeGrid));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'gridlayoutallBar.json'), JSON.stringify(allBarGrid));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'gridlayoutallLine.json'), JSON.stringify(allLineGrid));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'gridlayoutoneTable.json'), JSON.stringify(oneTableGrid));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'gridlayout.json'), JSON.stringify(indexOverViewGrid));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'widgetsallText.json'), JSON.stringify(allTextWidgets));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'widgetsallGauge.json'), JSON.stringify(allGaugeWidgets));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'widgetsallBar.json'), JSON.stringify(allBarWidgets));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'widgetsallLine.json'), JSON.stringify(allLineWidgets));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'widgetsoneTable.json'), JSON.stringify(oneTableWidgets));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'widgets.json'), JSON.stringify(indexOverViewWidgets));
    // fs.writeFileSync(path.join(__dirname+'/conf', 'devices.json'),JSON.stringify(deviceListJson));
    // make the options definition for all sensors(channels)
    // text widget option
    // allChildren.forEach(child);
  });
  socket.on('update-dashboard', (dashboards) => {
    var dashboardsJson = JSON.stringify(dashboards);
    // console.log(newWidgets);
    fs.writeFile(path.join(__dirname+'/conf', 'dashboards.json'), dashboardsJson, () => {
      // console.log(dashboards);
    });
    // Update allText.allGauge,allBar,allLine,oneTable's gridlayout.json,widgets.json
    // console.log(deviceList);
  });

//   socket.on('batch',(batchEvent)=>{
// // console.log(batchEvent);
// if (batchEvent.batchStatus == 'ON'){batches[batchEvent.deviceid] = batchEvent;}
// else {
//   // console.log(batches[batchEvent.deviceid],batchEvent);

//   delete batches[batchEvent.deviceid];
// }    
//   });
  socket.on('history-query', (query) => {
  // console.log(query);
    // this troubled me a lot,for not familiar with the ascync methods.
    let historyData = [];
    let promiseArr = [];
  query.collectionNames.forEach((collectionName)=>{
    let p = new Promise((resolve, reject) => {
      // 
      db.collection(collectionName).find({id:{$in:query.ids},timestamp:{$gt:query.historyFromTime,$lt:query.historyToTime}},{_id:0},(error,docs)=>{
        // console.log(docs); 
        // {id:0}
        historyData= historyData.concat(docs);
        resolve();
        // console.log(historyData);
      });
 
    });
    promiseArr.push(p)
  });
  // wait until all Promises resolved,send data to client.
  Promise.all(promiseArr).then(res => {
    // historyData.sort((a,b)=>{return a.timestamp - b.timestamp});
    // console.log(historyData[historyData.length-1])
    socket.emit('history-data',historyData);
  });
  });  // end of socket.on('history-query')

  // end of socket.on('connect)
});
var batches = {};

client.connectRTUBuffered(config.comport, {
  baudRate: 9600,parity:'odd'
});
// set timeout, if slave did not reply back
client.setTimeout(500);
// console.log(client);
// list of meter's id

var devicesList = JSON.parse(fs.readFileSync(path.join(__dirname+'/conf', 'devices.json'), 'utf-8')).filter(e =>{return e.enabled == true;});
// console.log(devicesList);
var deviceData = [];
// var history = {};
// var batchValue;
const getMetersValue = async (devicesList) => {
  try {
    // get value of all meters
    for (let device of devicesList) {
      // output value to console
      //console.log(await getMeterValue(meter));
      await getMeterValue(device);

    }
    // console.log(deviceData);
  } catch (e) {
    // if error, handle them here (it should not)
    console.log(e)
  } finally {
    // after get all data from salve repeate it again
    // wait 100ms before get another device


    // console.log(deviceData);
    // emit the fresh data to frontend through socket.io
    io.emit("update-device-data", deviceData);
    // Now ready to save the retrieved data to database,here is mongodb.
    var now = new Date();
    var collectionName = 'historyyear'+now.getFullYear().toString()+'month'+(now.getMonth()+1).toString();
    db.collection(collectionName).insertMany(deviceData,(err,docs)=>{});
// db.collection(collectionName).drop();
    await sleep(config.interval||3000);
    // clear the deviceData and read the new data.
    deviceData = [];
    setImmediate(() => {
      getMetersValue(devicesList);
    })
  }
}

const getMeterValue = async (device) => {
  try {
    // set ID of slave
    //console.log(device);
    await client.setID(device.address);
    // read the 1 registers starting at address 0 (first register)
    let val;
    switch (device.functionCode) {
      case 3:
        val = await client.readHoldingRegisters(device.startAddress, device.childCount);
        break;
      case 4:
        val = await client.readInputRegisters(device.startAddress, device.childCount);
        break;
      case 120:
        val = await client.readHoldingRegisters(device.startAddress, device.childCount*2);
        // val = await client.readHoldingRegisters(20247,16)
        // console.log(val.buffer);
        // console.log(val.buffer.slice(0,4).readFloatBE());
        // val.buffer
        // console.log(val);
        let valdata = [];
        for (i=0;i<device.childCount;i++){
          valdata.push(val.buffer.slice(i*4,i*4+4).readFloatBE());
        }
        // console.log(batches)
        // if (Object.keys(batches).length>0 && Object.keys(batches['d'+String(device.address)]).length>0 && batches['d'+String(device.address)].batchStatus == 'ON')
        if (valdata[0]>0)
        {
          //check if batch is on:
          if (batches.hasOwnProperty('d'+device.address)){
            //batch is already on
            // console.log(valdata);
            let bvcweight = valdata[8]-batches['d'+device.address].data[0];
            let bvcvolume = valdata[9]-batches['d'+device.address].data[1];
            valdata.push(bvcweight,bvcvolume);
            batches['d'+device.address].currentBatchValue = {batchWeight:bvcweight,batchVolume:bvcvolume,batchEndTime:Date.now()};
          }
          else{
            valdata.push(0,0);
            batches['d'+device.address] = {batchStatus:'ON',data:[valdata[8],valdata[9]],timestamp:Date.now()};
          }
          
          // valdata.push(valdata[6]-valdata)
        }
        else{
          valdata.push(0,0);
          if (batches.hasOwnProperty('d'+device.address)){
            // console.log(batches);
            const batchStartTimeString = new Date(batches['d'+device.address].timestamp).toLocaleString('en-GB');
            const batchEndTimeString = new Date(batches['d'+device.address].currentBatchValue.batchEndTime).toLocaleString('en-GB');
            let batchLog = `.LOG
On device ${device.id},name:${device.name},
Batch started on ${batchStartTimeString},
Batch ended on ${batchEndTimeString},
Batch weight: ${batches['d'+device.address].currentBatchValue.batchWeight} ${device.children[10].measureUnit},
Batch volume: ${batches['d'+device.address].currentBatchValue.batchVolume} ${device.children[11].measureUnit},or ${batches['d'+device.address].currentBatchValue.batchVolume*1000/159} bbl.
`;
            // console.log(batchLog);
            fs.writeFile('./data/batches/'+batchStartTimeString.replace(/\W/g,'-')+'to'+batchEndTimeString.replace(/\W/g,'-')+'---'+device.id+'.txt',batchLog,(err)=>{
              // console.log(err);
            });
            delete batches['d'+device.address];
          }
        }
// console.log()
        val.data = valdata;
        // console.log(batches);
        // console.log(valdata)
        break;
      default:
        val = await client.readHoldingRegisters(device.startAddress, device.childCount);
        break;
    }

    // return the value
    let deviceDataOriginal = val.data;
    // console.log(deviceDataOriginal);
    let deviceDataScaled = deviceDataOriginal.map((currentData, currentIndex) => {
      // for testing:Ramdon number
      // var currentValue = Number((Math.random() * device.children[currentIndex].maxAlarm * 1.2).toFixed(2));
      // for production:real number
      var currentValue = Number((currentData*device.children[currentIndex].scale).toFixed(3));
      // test production
      // let currentValue = Number((currentData*device.children[currentIndex].scale+Math.random()*20).toFixed(2));
      return {
        timestamp: Date.now(),
        id: device.children[currentIndex].id,
        value: currentValue,
        status: (() => {
          switch (true) {
            case currentValue <= device.children[currentIndex].minAlarm:
              return "minAlarm";

            case currentValue > device.children[currentIndex].minAlarm && currentValue < device.children[currentIndex].lowAlarm:
              return "lowAlarm";
            case currentValue > device.children[currentIndex].highAlarm && currentValue < device.children[currentIndex].maxAlarm:
              return "highAlarm";
            case currentValue >= device.children[currentIndex].maxAlarm:
              return "maxAlarm";
            default:
              return "normal";
          }
        })()
      }
    });
    

    deviceData = deviceData.concat(deviceDataScaled);
    // console.log(deviceDataScaled)
    // deviceData = deviceDataScaled.concat({timestamp:Date.now(),id:'d1cbw':});
    // return deviceDataScaled;
    // console.log(batch);
  } catch (e) {
    // if error return -1
    return e
  }
}

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));


// start get value
getMetersValue(devicesList);
//console.log(dd);

server.listen(port, () => {
  console.log(`application is running at: http://localhost:${port}`);
});