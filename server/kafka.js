import { Kafka, logLevel } from 'kafkajs';

// --- Kafka Client -----------------------------------------------------------

const kafka = new Kafka({
  clientId: 'event-security',
  brokers: ['localhost:9092'],
  logLevel: logLevel.WARN,
  retry: {
    initialRetryTime: 300,
    retries: 8,
    maxRetryTime: 30000,
  },
});

// Topics that must exist before producing / consuming
const REQUIRED_TOPICS = [
  'nsm-xdr-events',
  'nsm-original-alert',
  'nsm-incident-events',
  'nsm-incident-task',
];

// --- Admin helpers (topic creation) -----------------------------------------

async function ensureTopics() {
  const admin = kafka.admin();
  try {
    await admin.connect();

    const existing = await admin.listTopics();
    const toCreate = REQUIRED_TOPICS.filter((t) => !existing.includes(t));

    if (toCreate.length) {
      await admin.createTopics({
        topics: toCreate.map((topic) => ({
          topic,
          numPartitions: 3,
          replicationFactor: 1,
        })),
      });
      console.log('[kafka] created topics:', toCreate.join(', '));
    } else {
      console.log('[kafka] all required topics already exist');
    }
  } catch (err) {
    console.error('[kafka] ensureTopics error:', err.message);
  } finally {
    await admin.disconnect().catch(() => {});
  }
}

// --- Producer ----------------------------------------------------------------

let sharedProducer = null;

async function createProducer() {
  if (sharedProducer) return sharedProducer;

  const producer = kafka.producer({
    allowAutoTopicCreation: false,
  });

  try {
    await producer.connect();
    sharedProducer = producer;
    console.log('[kafka] producer connected');
    return producer;
  } catch (err) {
    console.error('[kafka] producer connect error:', err.message);
    throw err;
  }
}

// --- Consumer ----------------------------------------------------------------

async function createConsumer(topic, groupId, handler) {
  const consumer = kafka.consumer({
    groupId,
    allowAutoTopicCreation: false,
    sessionTimeout: 30000,
    heartbeatInterval: 3000,
  });

  try {
    await consumer.connect();
    console.log(`[kafka] consumer connected (group=${groupId}, topic=${topic})`);

    await consumer.subscribe({ topic, fromBeginning: true });

    await consumer.run({
      eachMessage: async ({ topic: msgTopic, partition, message }) => {
        try {
          const value = message.value
            ? JSON.parse(message.value.toString())
            : null;

          await handler({
            topic: msgTopic,
            partition,
            offset: message.offset,
            key: message.key ? message.key.toString() : null,
            value,
            headers: message.headers,
          });
        } catch (err) {
          console.error(
            `[kafka] handler error (topic=${topic}, group=${groupId}):`,
            err.message,
          );
        }
      },
    });

    return consumer;
  } catch (err) {
    console.error(
      `[kafka] consumer error (topic=${topic}, group=${groupId}):`,
      err.message,
    );
    throw err;
  }
}

// --- Send message ------------------------------------------------------------

async function sendMessage(topic, msg) {
  const producer = sharedProducer || (await createProducer());
  try {
    const payload =
      typeof msg === 'string' || Buffer.isBuffer(msg)
        ? msg
        : JSON.stringify(msg);

    await producer.send({
      topic,
      messages: [{ value: payload }],
    });
  } catch (err) {
    console.error(`[kafka] sendMessage error (topic=${topic}):`, err.message);
    throw err;
  }
}

// --- Initialise topics on module load ----------------------------------------

await ensureTopics();

// --- Exports ----------------------------------------------------------------

export { createProducer, createConsumer, sendMessage, ensureTopics };
