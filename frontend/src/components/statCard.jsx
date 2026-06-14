function StatCard({ title, value }) {
    return (
        <div style={{
            border: "1px solid #ccc",
            borderRadius: "10px",
            padding: "10px",
            margin: "10px"
        }}>   
            <h3>{title}</h3>
            <p>{value}</p>     
        </div>
    );
}
export default StatCard;