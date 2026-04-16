import React,{useState} from 'react'
import { useNavigate, Link } from 'react-router'
import "../auth.form.scss"
import { useAuth } from '../hooks/useAuth'

const Login = () => {

    const { loading, handleLogin } = useAuth()
    const navigate = useNavigate()

    const [ email, setEmail ] = useState("")
    const [ password, setPassword ] = useState("")

const handleSubmit = async (e) => {
    e.preventDefault();

    const res = await handleLogin({ email, password });

    if (res?.success) {
        navigate('/');
    }
};

    if(loading){
        return (<main><h1>Loading.......</h1></main>)
    }


return (
    <main className="auth-page">
        <div className="form-container">
            <h1>Welcome Back 👋</h1>
            <p className="subtitle">Login to continue</p>

            <form onSubmit={handleSubmit}>
                <div className="input-group">
                    <label>Email</label>
                    <input
                        onChange={(e) => setEmail(e.target.value)}
                        type="email"
                        placeholder="Enter your email"
                    />
                </div>

                <div className="input-group">
                    <label>Password</label>
                    <input
                        onChange={(e) => setPassword(e.target.value)}
                        type="password"
                        placeholder="Enter your password"
                    />
                </div>

                <button className="button primary-button">Login</button>
            </form>

            <p className="bottom-text">
                Don't have an account? <Link to="/register">Register</Link>
            </p>
        </div>
    </main>
);
}

export default Login