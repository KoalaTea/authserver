import { gql, useQuery } from "@apollo/client";

const query = gql`
    query GetUsers {
        users{
            id
            name
        }
    }
`

export const UserList = () => {

    // const { loading, error, data } = useQuery(query);
    const { data } = useQuery(query);


    return (
        <>
            <p>Testing 123</p>
            <div>
                {data?.users?.map((item: any) => {
                    return <div key={item?.id}>{item?.name}</div>
                })}
            </div>
        </>
    );
}