app.get('/search', (req, res) => {
  const q = req.query.q || ''; 
  res.type('text/plain');
  res.send(`Results for ${q}`); 
});
