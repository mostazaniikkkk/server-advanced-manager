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
-- /hola [texto]: cualquier jugador (permiso 0); responde a quien lo ejecutó
sam.command('hola', function(p, texto, args)
  local quien = p and p.name or 'consola'
  if #args == 0 then return '¡Hola, ' .. quien .. '!' end
  return '¡Hola, ' .. quien .. '! Dijiste ' .. #args .. ' palabras: ' .. texto
end)

-- /anuncio <texto>: solo operadores (permiso 2)
sam.command('anuncio', function(p, texto)
  if texto == '' then return 'Uso: /anuncio <texto>' end
  sam.broadcast('[Anuncio] ' .. texto)
end, {permission = 2})