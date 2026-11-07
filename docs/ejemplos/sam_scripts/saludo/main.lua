sam.log('cargado')
sam.on('join', function(p)
  sam.log('entró ' .. p.name .. ' (en línea: ' .. #sam.players() .. ')')
  sam.tell(p.name, '¡Bienvenido, ' .. p.name .. '! Esto lo dice un script Lua de SAM.')
end)
sam.on('quit', function(p) sam.log('salió ' .. p.name) end)
local n = 0
sam.every(100, function()
  n = n + 1
  if n <= 2 then sam.log('van ' .. (n * 5) .. ' segundos') end
end)