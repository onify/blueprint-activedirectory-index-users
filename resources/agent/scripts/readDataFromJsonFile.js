var jsonFile = process.argv[2];
var offset = Number(process.argv[3]) || 0;
var limit = Number(process.argv[4]) || 10;

var result = {
  error: {
    error: false,
    code: null,
    message: null
  },
  meta: {
    offset: offset,
    limit: limit,
    total: 0,
    records: 0
  },
  records: []
};

const fs = require('fs');

function jsonReader(filePath, r) {
  fs.readFile(filePath, (err, fileData) => {
    if (err) {
      return r && r(err);
    }
    try {
      const object = JSON.parse(fileData.toString('utf8').replace(/^\uFEFF/, ''));
      return r && r(null, object);
    } catch(err) {
      return r && r(err);
    }
  });
}

jsonReader(jsonFile, (err, records) => {
  if (err) {
    result.error = {
      error: true,
      code: err.code,
      message: err.message
    };
  } else {
    result.meta.total = records.length;
    result.records = records.slice(offset, offset + limit);
    result.meta.records = result.records.length;
  }
  var myJSON = JSON.stringify(result);
  console.log(myJSON); // eslint-disable-line no-console
});
