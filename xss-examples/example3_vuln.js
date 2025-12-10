const express = require('express');
const app = express();

app.get('/search', (req, res) => {
  const q = req.query.q || '';

  res.json({
    message: "Results found",
    searchTerm: q
  });
});

app.listen(3000, () => console.log('Server running'));
