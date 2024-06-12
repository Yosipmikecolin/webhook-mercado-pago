import express from "express"
import crypto from "crypto"
import fetch from "node-fetch"
import cors from "cors"

const app = express();
app.use(express.json());
app.use(cors());

app.listen

app.post('/webhook', async (req, res) => {
  try {

    console.log("REQUEST",req)
    // Obtén la firma del encabezado x-signature
    const xSignature = req.header('x-signature');

    if (typeof xSignature === 'string') {
      console.log('x-signature recibido:', xSignature);

      // Separar la firma en partes
      const parts = xSignature.split(',');

      // Inicializar variables para almacenar ts y hash
      let ts = null;
      let hash = null;

      // Iterar sobre las partes para obtener ts y v1
      parts.forEach((part) => {
        const [key, value] = part.split('=');
        if (key.trim() === 'ts') {
          ts = value.trim();
        } else if (key.trim() === 'v1') {
          hash = value.trim();
        }
      });

      // Verificar que todos los valores necesarios estén presentes
      if (!ts || !hash) {
        console.error('Faltan valores en el encabezado x-signature. ts:', ts, ' hash:', hash);
        return res.status(400).json({ message: 'Bad Request' });
      }

      // Obtener el ID de la transacción del cuerpo de la solicitud
      const requestBody = req.body;
      console.log('requestBody recibido:', requestBody);
      const dataId = requestBody.data?.id;
      const filename = requestBody.data?.metadata.filename;
      const token = requestBody.data?.metadata.token;
      const address = requestBody.data?.metadata.address;
      const user_id = requestBody.data?.metadata.user_id;

      if (!dataId) {
        console.error('data.id no está presente en el cuerpo de la solicitud.');
        return res.status(400).json({ message: 'Bad Request' });
      }

      // Generar el manifiesto
      const requestId = req.header('x-request-id');
      const manifest = `id:${dataId};request-id:${requestId};ts:${ts};`;
      console.log('manifest:', manifest);

      // Obtener la clave secreta de Mercado Pago
      const secret = process.env.NEXT_PUBLIC_KEY_SECRET_WEBHOOK || '';
      if (!secret) {
        console.error('Clave secreta no configurada.');
        return res.status(500).json({ message: 'Internal Server Error' });
      }

      // Crear una firma HMAC
      const hmac = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
      console.log('hmac:', hmac);

      // Verificar la firma
      if (hmac === hash) {
        try {
          const response = await fetch(`https://notificaci-n-websocket.onrender.com/api/get-data/${filename}`, {
            method: 'GET',
          });
          const dataOrder = await response.json();

          await fetch('https://strapi-games.up.railway.app/api/orders', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({
              data: {
                user: user_id,
                totalPayment: dataOrder.reduce((sum, item) => (sum += Number(item.total)), 0),
                idPayment: 345,
                address: address ? Number(address) : 0,
                products: dataOrder,
                dateOrder: new Date(),
              },
            }),
          });

          res.json({ message: 'OK' });
        } catch (apiError) {
          console.error('Error al realizar las solicitudes a las APIs:', apiError);
          res.status(500).json({ message: 'Internal Server Error', apiError });
        }
      } else {
        // La verificación HMAC falló
        console.error('Fallo en la verificación HMAC. Esperado:', hash, ' Calculado:', hmac);
        res.status(400).json({ message: 'Bad Request' });
      }
    } else {
      console.error('El encabezado x-signature no es una cadena o no está presente.');
      res.status(400).json({ message: 'Bad Request' });
    }
  } catch (error) {
    console.error('Error al manejar el webhook:', error);
    res.status(500).json({ message: 'Internal Server Error' });
  }
});

// Configura el puerto en el que escuchará la aplicación
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Servidor escuchando en el puerto ${PORT}`);
});
