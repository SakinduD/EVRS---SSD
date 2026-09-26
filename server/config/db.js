import dns from "dns";
import mongoose from "mongoose";

const connectDB = async () => {
  // mongodb+srv URIs need an SRV lookup through Node's own resolver, which on
  // some Windows setups falls back to 127.0.0.1 and gets ECONNREFUSED. Opt-in
  // override, e.g. DNS_SERVERS=8.8.8.8,1.1.1.1
  if (process.env.DNS_SERVERS) {
    dns.setServers(process.env.DNS_SERVERS.split(",").map((s) => s.trim()));
  }

  try {
    const conn = await mongoose.connect(process.env.MONGO_URI);
    console.log(`MongoDB Connected: ${conn.connection.host}`);
  } catch (error) {
    console.error(`Error: ${error.message}`);
    process.exit(1);
  }
};

export default connectDB;
