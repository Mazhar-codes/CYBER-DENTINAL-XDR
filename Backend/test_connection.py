"""
Quick test script to verify backend is emitting events
Run this while backend is running to test Socket.IO connection
"""
import socketio
import asyncio

sio = socketio.AsyncClient()

@sio.event
async def connect():
    print("✅ Connected to backend!")
    print("Waiting for network events...")

@sio.event
async def network(data):
    print(f"📡 Received network event:")
    print(f"   Source: {data.get('source_ip')} -> Dest: {data.get('destination_ip')}")
    print(f"   Prediction: {data.get('prediction')}, Score: {data.get('anomaly_score')}")

@sio.event
async def disconnect():
    print("❌ Disconnected from backend")

async def main():
    try:
        await sio.connect("http://127.0.0.1:8000", transports=["websocket"])
        print("Connected! Waiting for events (press Ctrl+C to stop)...")
        await sio.wait()
    except KeyboardInterrupt:
        print("\nStopping...")
    finally:
        await sio.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
